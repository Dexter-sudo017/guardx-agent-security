from __future__ import annotations

import hashlib
import json
import os
from functools import lru_cache
from pathlib import Path
from time import perf_counter
from typing import Any

from app.models import AnalysisResult
from app.guards.segment_role_features import PROFILE_SELECTOR_FEATURE_NAMES, build_profile_selector_feature_values


PROJECT_ROOT = Path(__file__).resolve().parents[5]
ONLINE_POLICY_PATH = PROJECT_ROOT / "configs" / "embedding_guard_policy_qwen3_joint_online.json"


def _resolve(path: str) -> Path:
    item = Path(path)
    return item if item.is_absolute() else PROJECT_ROOT / item


def _policy_path_from_env() -> Path:
    override = os.environ.get("GUARDX_QWEN3_ONLINE_POLICY_PATH")
    return _resolve(override) if override else ONLINE_POLICY_PATH


@lru_cache(maxsize=8)
def _load_online_policy_from_path(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def load_online_policy() -> dict[str, Any]:
    return _load_online_policy_from_path(str(_policy_path_from_env()))


def clear_online_cache() -> None:
    _load_online_policy_from_path.cache_clear()
    _load_online_components.cache_clear()


def _seed_for(text: str, sample_index: int) -> int:
    digest = hashlib.sha256(f"{sample_index}:{text}:qwen3_joint_online".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % (2**31)


def _env_float(name: str, fallback: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return fallback
    try:
        return float(raw)
    except ValueError:
        return fallback


def _env_int(name: str, fallback: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return fallback
    try:
        return int(raw)
    except ValueError:
        return fallback


def _normalise_segments(text: str, surface: str, segments: list[tuple[str, str]] | None = None) -> list[tuple[str, str]]:
    if segments:
        cleaned = [(str(kind or "user"), str(value).strip()) for kind, value in segments if str(value).strip()]
        if cleaned:
            return cleaned
    if surface == "agent_tool":
        return [("agent", text)]
    return [("user", text)]


@lru_cache(maxsize=1)
def _load_online_components():
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    from transformers import AutoModel, AutoTokenizer

    policy = load_online_policy()
    checkpoint_path = _resolve(str(policy["checkpoint"]))
    checkpoint = torch.load(checkpoint_path, map_location="cpu", weights_only=True)
    input_dim = int(checkpoint["input_dim"])
    hidden_dim = int(checkpoint["hidden_dim"])

    class InversionAwareDenoiser(nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.net = nn.Sequential(
                nn.LayerNorm(input_dim),
                nn.Linear(input_dim, hidden_dim),
                nn.GELU(),
                nn.Dropout(0.05),
                nn.Linear(hidden_dim, input_dim),
            )
            self.risk_head = nn.Sequential(
                nn.LayerNorm(input_dim),
                nn.Linear(input_dim, hidden_dim // 2),
                nn.GELU(),
                nn.Linear(hidden_dim // 2, 1),
            )

        def forward(self, noisy):
            denoised = F.normalize(noisy + self.net(noisy), p=2, dim=-1)
            return denoised, self.risk_head(denoised).squeeze(-1)

    class CleanLogitRiskAdapter(nn.Module):
        def __init__(self, adapter_input_dim: int, adapter_hidden_dim: int, include_clean: bool, include_backbone_logit: bool) -> None:
            super().__init__()
            self.include_clean = include_clean
            self.include_backbone_logit = include_backbone_logit
            total_dim = adapter_input_dim
            if include_clean:
                total_dim += adapter_input_dim
            if include_backbone_logit:
                total_dim += 1
            self.net = nn.Sequential(
                nn.LayerNorm(total_dim),
                nn.Linear(total_dim, adapter_hidden_dim),
                nn.GELU(),
                nn.Dropout(0.1),
                nn.Linear(adapter_hidden_dim, adapter_hidden_dim // 2),
                nn.GELU(),
                nn.Linear(adapter_hidden_dim // 2, 1),
            )

        def forward(self, denoised, base_logit, clean):
            values = denoised
            if self.include_clean:
                values = torch.cat([values, clean], dim=-1)
            if self.include_backbone_logit:
                values = torch.cat([values, base_logit.unsqueeze(-1)], dim=-1)
            return self.net(values).squeeze(-1)

    class SegmentAwareDualHeadAdapter(nn.Module):
        def __init__(
            self,
            adapter_input_dim: int,
            adapter_dim: int,
            layers: int,
            heads: int,
            dropout: float,
            surface_count: int,
            segment_count: int,
        ) -> None:
            super().__init__()
            self.proj = nn.Linear(adapter_input_dim, adapter_dim)
            self.safe_cls = nn.Parameter(torch.zeros(1, 1, adapter_dim))
            self.active_cls = nn.Parameter(torch.zeros(1, 1, adapter_dim))
            self.surface = nn.Embedding(surface_count, adapter_dim)
            self.segment = nn.Embedding(segment_count, adapter_dim)
            layer = nn.TransformerEncoderLayer(
                d_model=adapter_dim,
                nhead=heads,
                dim_feedforward=adapter_dim * 4,
                dropout=dropout,
                activation="gelu",
                batch_first=True,
                norm_first=True,
            )
            self.encoder = nn.TransformerEncoder(layer, num_layers=layers)
            self.norm = nn.LayerNorm(adapter_dim)
            self.safe_head = nn.Sequential(nn.Dropout(dropout), nn.Linear(adapter_dim, 1))
            self.active_head = nn.Sequential(nn.Dropout(dropout), nn.Linear(adapter_dim, 1))

        def forward(self, values, masks, token_segments, surfaces):
            tokens = self.proj(values) + self.segment(token_segments)
            surface_bias = self.surface(surfaces).unsqueeze(1)
            safe_cls = self.safe_cls.expand(tokens.shape[0], -1, -1) + surface_bias
            active_cls = self.active_cls.expand(tokens.shape[0], -1, -1) + surface_bias
            encoded_input = torch.cat([safe_cls, active_cls, tokens], dim=1)
            cls_mask = torch.ones((masks.shape[0], 2), dtype=masks.dtype, device=masks.device)
            full_mask = torch.cat([cls_mask, masks], dim=1).bool()
            encoded = self.encoder(encoded_input, src_key_padding_mask=~full_mask)
            safe = self.safe_head(self.norm(encoded[:, 0])).squeeze(-1)
            active = self.active_head(self.norm(encoded[:, 1])).squeeze(-1)
            return safe, active

    class PooledSegmentDualHeadAdapter(nn.Module):
        def __init__(
            self,
            adapter_input_dim: int,
            adapter_dim: int,
            layers: int,
            heads: int,
            dropout: float,
            surface_count: int,
            segment_count: int,
        ) -> None:
            super().__init__()
            self.proj = nn.Linear(adapter_input_dim, adapter_dim)
            self.safe_cls = nn.Parameter(torch.zeros(1, 1, adapter_dim))
            self.active_cls = nn.Parameter(torch.zeros(1, 1, adapter_dim))
            self.surface = nn.Embedding(surface_count, adapter_dim)
            self.segment = nn.Embedding(segment_count, adapter_dim)
            layer = nn.TransformerEncoderLayer(
                d_model=adapter_dim,
                nhead=heads,
                dim_feedforward=adapter_dim * 4,
                dropout=dropout,
                activation="gelu",
                batch_first=True,
                norm_first=True,
            )
            self.encoder = nn.TransformerEncoder(layer, num_layers=layers)
            self.norm = nn.LayerNorm(adapter_dim)
            self.safe_head = nn.Sequential(nn.Dropout(dropout), nn.Linear(adapter_dim, 1))
            self.active_head = nn.Sequential(nn.Dropout(dropout), nn.Linear(adapter_dim, 1))

        def forward(self, pooled, segment_mask, token_segments, surfaces):
            tokens = self.proj(pooled) + self.segment(token_segments)
            surface_bias = self.surface(surfaces).unsqueeze(1)
            safe_cls = self.safe_cls.expand(tokens.shape[0], -1, -1) + surface_bias
            active_cls = self.active_cls.expand(tokens.shape[0], -1, -1) + surface_bias
            encoded_input = torch.cat([safe_cls, active_cls, tokens], dim=1)
            cls_mask = torch.ones((segment_mask.shape[0], 2), dtype=segment_mask.dtype, device=segment_mask.device)
            full_mask = torch.cat([cls_mask, segment_mask], dim=1).bool()
            encoded = self.encoder(encoded_input, src_key_padding_mask=~full_mask)
            safe = self.safe_head(self.norm(encoded[:, 0])).squeeze(-1)
            active = self.active_head(self.norm(encoded[:, 1])).squeeze(-1)
            return safe, active

    class SurfaceScoreCalibrator(nn.Module):
        def __init__(self, feature_dim: int) -> None:
            super().__init__()
            self.net = nn.Sequential(
                nn.LayerNorm(feature_dim),
                nn.Linear(feature_dim, 64),
                nn.GELU(),
                nn.Dropout(0.08),
                nn.Linear(64, 32),
                nn.GELU(),
                nn.Linear(32, 1),
            )

        def forward(self, features):
            return self.net(features).squeeze(-1)

    class SegmentRoleProfileSelector(nn.Module):
        def __init__(self, feature_dim: int, hidden_dim: int) -> None:
            super().__init__()
            self.net = nn.Sequential(
                nn.LayerNorm(feature_dim),
                nn.Linear(feature_dim, hidden_dim),
                nn.GELU(),
                nn.Dropout(0.0),
                nn.Linear(hidden_dim, max(16, hidden_dim // 2)),
                nn.GELU(),
                nn.Linear(max(16, hidden_dim // 2), 1),
            )

        def forward(self, features):
            return self.net(features).squeeze(-1)

    class SegmentRoleSuppressionSelector(nn.Module):
        def __init__(self, feature_dim: int, hidden_dim: int) -> None:
            super().__init__()
            self.trunk = nn.Sequential(
                nn.LayerNorm(feature_dim),
                nn.Linear(feature_dim, hidden_dim),
                nn.GELU(),
                nn.Dropout(0.0),
                nn.Linear(hidden_dim, max(16, hidden_dim // 2)),
                nn.GELU(),
            )
            self.suppression_head = nn.Linear(max(16, hidden_dim // 2), 1)

        def forward(self, features):
            return self.suppression_head(self.trunk(features)).squeeze(-1)

    requested_device = os.environ.get("GUARDX_QWEN3_ONLINE_DEVICE") or str(policy.get("device", "auto"))
    device = "cuda" if requested_device == "cuda" or (requested_device == "auto" and torch.cuda.is_available()) else "cpu"
    guard = InversionAwareDenoiser().to(device)
    guard.load_state_dict(checkpoint["state_dict"])
    guard.eval()
    adapter = None
    adapter_metadata: dict[str, Any] = {"enabled": False}
    adapter_path_value = policy.get("adapter_checkpoint")
    if policy.get("adapter_enabled", False) and adapter_path_value:
        adapter_path = _resolve(str(adapter_path_value))
        adapter_checkpoint = torch.load(adapter_path, map_location=device, weights_only=True)
        adapter = CleanLogitRiskAdapter(
            adapter_input_dim=int(adapter_checkpoint.get("input_dim", input_dim)),
            adapter_hidden_dim=int(adapter_checkpoint.get("hidden_dim", input_dim)),
            include_clean=bool(adapter_checkpoint.get("include_clean", False)),
            include_backbone_logit=bool(adapter_checkpoint.get("include_backbone_logit", False)),
        ).to(device)
        adapter.load_state_dict(adapter_checkpoint["state_dict"])
        adapter.eval()
        adapter_metadata = {
            "enabled": True,
            "path": str(adapter_path),
            "include_clean": bool(adapter_checkpoint.get("include_clean", False)),
            "include_backbone_logit": bool(adapter_checkpoint.get("include_backbone_logit", False)),
            "threshold": adapter_checkpoint.get("threshold"),
        }
    model_name = str(policy["model_name"])
    tokenizer = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True, use_fast=False)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token or tokenizer.unk_token
    model_kwargs: dict[str, Any] = {"trust_remote_code": True}
    if bool(policy.get("low_cpu_mem_usage", False)):
        model_kwargs["low_cpu_mem_usage"] = True
    dtype_name = str(policy.get("torch_dtype", "")).lower()
    if dtype_name in {"float16", "fp16"} and device == "cuda":
        model_kwargs["dtype"] = torch.float16
    elif dtype_name in {"bfloat16", "bf16"} and device == "cuda":
        model_kwargs["dtype"] = torch.bfloat16
    try:
        encoder = AutoModel.from_pretrained(model_name, **model_kwargs).to(device)
    except TypeError as exc:
        if "dtype" not in model_kwargs:
            raise
        model_kwargs["torch_dtype"] = model_kwargs.pop("dtype")
        encoder = AutoModel.from_pretrained(model_name, **model_kwargs).to(device)
    encoder.eval()
    safe_frame_mlp = None
    safe_frame_mlp_metadata: dict[str, Any] = {"enabled": False}
    safe_frame_config = dict(policy.get("safe_frame_embedding_mlp", {}))
    if safe_frame_config.get("enabled", False) and safe_frame_config.get("checkpoint"):
        mlp_path = _resolve(str(safe_frame_config["checkpoint"]))
        mlp_checkpoint = torch.load(mlp_path, map_location=device, weights_only=False)
        mlp_input_dim = int(mlp_checkpoint["input_dim"])
        safe_frame_mlp = nn.Sequential(
            nn.LayerNorm(mlp_input_dim),
            nn.Linear(mlp_input_dim, 256),
            nn.GELU(),
            nn.Dropout(0.15),
            nn.Linear(256, 128),
            nn.GELU(),
            nn.Dropout(0.1),
            nn.Linear(128, 1),
            nn.Flatten(0),
        ).to(device)
        safe_frame_mlp.load_state_dict(mlp_checkpoint["state_dict"])
        safe_frame_mlp.eval()
        threshold_value = safe_frame_config.get("threshold", mlp_checkpoint.get("threshold", 0.5))
        safe_frame_mlp_metadata = {
            "enabled": True,
            "path": str(mlp_path),
            "threshold": float(threshold_value),
            "feature_mean": mlp_checkpoint["feature_mean"],
            "feature_std": mlp_checkpoint["feature_std"],
        }
    segment_dual_head = None
    segment_dual_head_metadata: dict[str, Any] = {"enabled": False}
    segment_score_calibrator = None
    segment_score_calibrator_metadata: dict[str, Any] = {"enabled": False}
    segment_high_recall_dual_head = None
    segment_profile_selector = None
    segment_profile_base_selector = None
    segment_profile_selector_metadata: dict[str, Any] = {"enabled": False}
    segment_config = dict(policy.get("segment_aware_dual_head", {}))
    if segment_config.get("enabled", False) and segment_config.get("checkpoint"):
        dual_path = _resolve(str(segment_config["checkpoint"]))
        dual_checkpoint = torch.load(dual_path, map_location=device, weights_only=True)
        surfaces = list(dual_checkpoint.get("surfaces", ["default", "chat", "agent_tool", "rag", "vlm_ocr"]))
        segment_types = list(dual_checkpoint.get("segment_types", ["user", "agent", "context", "ocr", "vlm", "visual", "metadata"]))
        architecture = str(dual_checkpoint.get("architecture", "token_segment_dual_head_v1"))
        adapter_cls = PooledSegmentDualHeadAdapter if architecture == "pooled_segment_dual_head_v1" else SegmentAwareDualHeadAdapter
        segment_dual_head = adapter_cls(
            adapter_input_dim=int(dual_checkpoint.get("input_dim", input_dim)),
            adapter_dim=int(dual_checkpoint.get("adapter_dim", 128)),
            layers=int(dual_checkpoint.get("layers", 2)),
            heads=int(dual_checkpoint.get("heads", 4)),
            dropout=float(dual_checkpoint.get("dropout", 0.0)),
            surface_count=len(surfaces),
            segment_count=len(segment_types),
        ).to(device)
        segment_dual_head.load_state_dict(dual_checkpoint["state_dict"])
        segment_dual_head.eval()
        segment_dual_head_metadata = {
            "enabled": True,
            "path": str(dual_path),
            "architecture": architecture,
            "safe_threshold": float(segment_config.get("safe_threshold", dual_checkpoint.get("safe_threshold", 0.5))),
            "active_threshold": float(segment_config.get("active_threshold", dual_checkpoint.get("active_threshold", 0.5))),
            "input_dim": int(dual_checkpoint.get("input_dim", input_dim)),
            "surfaces": surfaces,
            "segment_types": segment_types,
            "max_segments": int(segment_config.get("max_segments", dual_checkpoint.get("max_segments", 4))),
            "max_segment_length": int(segment_config.get("max_segment_length", dual_checkpoint.get("max_segment_length", 64))),
            "risk_floor": float(segment_config.get("risk_floor", 1.0)),
            "force_active_intent_floor": bool(segment_config.get("force_active_intent_floor", True)),
        }
        calibrator_config = dict(segment_config.get("surface_score_calibrator", {}))
        if calibrator_config.get("enabled", False) and calibrator_config.get("checkpoint"):
            calibrator_path = _resolve(str(calibrator_config["checkpoint"]))
            calibrator_checkpoint = torch.load(calibrator_path, map_location=device, weights_only=False)
            segment_score_calibrator = SurfaceScoreCalibrator(int(calibrator_checkpoint["input_dim"])).to(device)
            segment_score_calibrator.load_state_dict(calibrator_checkpoint["state_dict"])
            segment_score_calibrator.eval()
            segment_score_calibrator_metadata = {
                "enabled": True,
                "path": str(calibrator_path),
                "architecture": str(calibrator_checkpoint.get("architecture", "pooled_dual_head_surface_score_calibrator_v1")),
                "threshold": float(calibrator_config.get("threshold", calibrator_checkpoint.get("threshold", segment_dual_head_metadata["active_threshold"]))),
                "feature_mean": calibrator_checkpoint["feature_mean"],
                "feature_std": calibrator_checkpoint["feature_std"],
                "surfaces": list(calibrator_checkpoint.get("surfaces", surfaces)),
            }
        profile_selector_config = dict(segment_config.get("profile_selector", {}))
        if profile_selector_config.get("enabled", False) and profile_selector_config.get("checkpoint"):
            selector_path = _resolve(str(profile_selector_config["checkpoint"]))
            selector_checkpoint = torch.load(selector_path, map_location=device, weights_only=False)
            high_checkpoint_value = profile_selector_config.get("high_recall_checkpoint") or selector_checkpoint.get("high_recall_checkpoint")
            if not high_checkpoint_value:
                raise ValueError("segment profile selector enabled without high_recall_checkpoint")
            high_path = _resolve(str(high_checkpoint_value))
            high_checkpoint = torch.load(high_path, map_location=device, weights_only=True)
            high_architecture = str(high_checkpoint.get("architecture", architecture))
            high_cls = PooledSegmentDualHeadAdapter if high_architecture == "pooled_segment_dual_head_v1" else SegmentAwareDualHeadAdapter
            segment_high_recall_dual_head = high_cls(
                adapter_input_dim=int(high_checkpoint.get("input_dim", input_dim)),
                adapter_dim=int(high_checkpoint.get("adapter_dim", 128)),
                layers=int(high_checkpoint.get("layers", 2)),
                heads=int(high_checkpoint.get("heads", 4)),
                dropout=float(high_checkpoint.get("dropout", 0.0)),
                surface_count=len(list(high_checkpoint.get("surfaces", surfaces))),
                segment_count=len(list(high_checkpoint.get("segment_types", segment_types))),
            ).to(device)
            segment_high_recall_dual_head.load_state_dict(high_checkpoint["state_dict"])
            segment_high_recall_dual_head.eval()
            feature_names = list(selector_checkpoint.get("feature_names", PROFILE_SELECTOR_FEATURE_NAMES))
            selector_architecture = str(selector_checkpoint.get("architecture", "segment_role_profile_selector_v1"))
            if selector_architecture == "segment_role_profile_selector_v2":
                segment_profile_selector = SegmentRoleSuppressionSelector(
                    int(selector_checkpoint["input_dim"]),
                    int(selector_checkpoint.get("hidden_dim", 64)),
                ).to(device)
                base_checkpoint_value = selector_checkpoint.get("base_selector_checkpoint")
                if not base_checkpoint_value:
                    raise ValueError("segment role v2 selector enabled without base_selector_checkpoint")
                base_path = _resolve(str(base_checkpoint_value))
                base_checkpoint = torch.load(base_path, map_location=device, weights_only=False)
                segment_profile_base_selector = SegmentRoleProfileSelector(
                    int(base_checkpoint["input_dim"]),
                    int(base_checkpoint.get("hidden_dim", 64)),
                ).to(device)
                segment_profile_base_selector.load_state_dict(base_checkpoint["state_dict"])
                segment_profile_base_selector.eval()
            else:
                base_checkpoint = None
                base_path = None
                segment_profile_selector = SegmentRoleProfileSelector(
                    int(selector_checkpoint["input_dim"]),
                    int(selector_checkpoint.get("hidden_dim", 64)),
                ).to(device)
            segment_profile_selector.load_state_dict(selector_checkpoint["state_dict"])
            segment_profile_selector.eval()
            segment_profile_selector_metadata = {
                "enabled": True,
                "path": str(selector_path),
                "architecture": selector_architecture,
                "threshold": float(profile_selector_config.get("threshold", selector_checkpoint.get("threshold", selector_checkpoint.get("escalation_threshold", 0.5)))),
                "escalation_threshold": float(profile_selector_config.get("escalation_threshold", selector_checkpoint.get("escalation_threshold", selector_checkpoint.get("threshold", 0.5)))),
                "suppression_threshold": float(profile_selector_config.get("suppression_threshold", selector_checkpoint.get("suppression_threshold", 1.1))),
                "decision_mode": str(selector_checkpoint.get("decision_mode", "strict_or_selector_escalation")),
                "feature_mean": selector_checkpoint["feature_mean"],
                "feature_std": selector_checkpoint["feature_std"],
                "feature_names": feature_names,
                "base_path": str(base_path) if base_path is not None else None,
                "base_feature_mean": selector_checkpoint.get("base_feature_mean") if selector_architecture == "segment_role_profile_selector_v2" else None,
                "base_feature_std": selector_checkpoint.get("base_feature_std") if selector_architecture == "segment_role_profile_selector_v2" else None,
                "base_feature_names": list(selector_checkpoint.get("base_feature_names", [])) if selector_architecture == "segment_role_profile_selector_v2" else [],
                "base_input_dim": selector_checkpoint.get("base_input_dim"),
                "high_recall_path": str(high_path),
                "high_safe_threshold": float(profile_selector_config.get("high_safe_threshold", selector_checkpoint.get("high_safe_threshold", 0.5))),
                "high_active_threshold": float(profile_selector_config.get("high_active_threshold", selector_checkpoint.get("high_active_threshold", 0.5))),
                "high_architecture": high_architecture,
            }
    return (
        torch,
        F,
        tokenizer,
        encoder,
        guard,
        adapter,
        adapter_metadata,
        safe_frame_mlp,
        safe_frame_mlp_metadata,
        segment_dual_head,
        segment_dual_head_metadata,
        segment_score_calibrator,
        segment_score_calibrator_metadata,
        segment_high_recall_dual_head,
        segment_profile_selector,
        segment_profile_base_selector,
        segment_profile_selector_metadata,
        device,
    )


def analyze(text: str, enabled: bool | None = None, surface: str = "default", segments: list[tuple[str, str]] | None = None) -> AnalysisResult:
    policy = load_online_policy()
    if enabled is False or not policy.get("enabled", True):
        return AnalysisResult(risk_score=0.0, labels=["qwen3_joint_online_disabled"], evidence=[], metadata={"enabled": False})
    started = perf_counter()
    (
        torch,
        F,
        tokenizer,
        encoder,
        guard,
        adapter,
        adapter_metadata,
        safe_frame_mlp,
        safe_frame_mlp_metadata,
        segment_dual_head,
        segment_dual_head_metadata,
        segment_score_calibrator,
        segment_score_calibrator_metadata,
        segment_high_recall_dual_head,
        segment_profile_selector,
        segment_profile_base_selector,
        segment_profile_selector_metadata,
        device,
    ) = _load_online_components()
    max_length = int(policy.get("max_length", 384))
    pooling = str(policy.get("pooling", "last"))
    threshold = _env_float("GUARDX_QWEN3_ONLINE_THRESHOLD", float(policy.get("threshold", 0.638943)))
    dp = dict(policy.get("dp", {}))
    samples = max(1, _env_int("GUARDX_QWEN3_ONLINE_DP_SAMPLES", int(dp.get("samples", 1))))
    noise_std = _env_float("GUARDX_QWEN3_ONLINE_NOISE_STD", float(dp.get("noise_std", 0.0))) if dp.get("enabled", True) else 0.0
    clip_norm = _env_float("GUARDX_QWEN3_ONLINE_CLIP_NORM", float(dp.get("clip_norm", 1.0)))
    with torch.no_grad():
        encoded = tokenizer(text, return_tensors="pt", truncation=True, max_length=max_length, padding=True).to(device)
        output = encoder(**encoded)
        hidden = output.last_hidden_state
        if pooling == "last":
            lengths = encoded["attention_mask"].sum(dim=1).clamp(min=1) - 1
            clean = hidden[torch.arange(hidden.shape[0], device=device), lengths]
        else:
            mask = encoded["attention_mask"].unsqueeze(-1)
            clean = (hidden * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1)
        clean = F.normalize(clean, p=2, dim=-1)
        clean = clean * min(1.0, clip_norm / max(float(torch.linalg.vector_norm(clean).detach().cpu()), 1e-12))
        probabilities = []
        base_probabilities = []
        cosines = []
        for sample_index in range(samples):
            generator = torch.Generator(device=device if str(device).startswith("cuda") else "cpu")
            generator.manual_seed(_seed_for(text, sample_index))
            noisy = F.normalize(clean + torch.randn(clean.shape, generator=generator, device=device) * noise_std, p=2, dim=-1)
            denoised, base_logits = guard(noisy)
            logits = adapter(denoised, base_logits, clean) if adapter is not None else base_logits
            base_probabilities.append(float(torch.sigmoid(base_logits)[0].detach().cpu()))
            probabilities.append(float(torch.sigmoid(logits)[0].detach().cpu()))
            cosines.append(float(F.cosine_similarity(clean, denoised, dim=-1)[0].detach().cpu()))
        safe_frame_mlp_result: dict[str, Any] = {"enabled": False}
        if safe_frame_mlp is not None and safe_frame_mlp_metadata.get("enabled"):
            surface_names = ["default", "chat", "agent_tool", "rag", "vlm_ocr"]
            surface_vec = torch.zeros((1, len(surface_names)), dtype=torch.float32, device=device)
            if surface in surface_names:
                surface_vec[0, surface_names.index(surface)] = 1.0
            lengths = torch.tensor(
                [[float(len(text)), float(len(text.split()))]],
                dtype=torch.float32,
                device=device,
            )
            lengths = torch.log1p(lengths)
            feature = torch.cat([clean.float(), surface_vec, lengths], dim=-1)
            mean = torch.as_tensor(safe_frame_mlp_metadata["feature_mean"], dtype=torch.float32, device=device)
            std = torch.as_tensor(safe_frame_mlp_metadata["feature_std"], dtype=torch.float32, device=device)
            feature = (feature - mean) / std
            mlp_score = float(torch.sigmoid(safe_frame_mlp(feature))[0].detach().cpu())
            mlp_threshold = float(safe_frame_mlp_metadata["threshold"])
            safe_frame_mlp_result = {
                "enabled": True,
                "score": round(mlp_score, 6),
                "threshold": round(mlp_threshold, 6),
                "is_risky": bool(mlp_score >= mlp_threshold),
                "is_safe_frame": bool(mlp_score < mlp_threshold),
                "path": safe_frame_mlp_metadata["path"],
            }
        segment_dual_head_result: dict[str, Any] = {"enabled": False}
        if segment_dual_head is not None and segment_dual_head_metadata.get("enabled"):
            surface_names = list(segment_dual_head_metadata["surfaces"])
            segment_names = list(segment_dual_head_metadata["segment_types"])
            max_segments = int(segment_dual_head_metadata["max_segments"])
            max_segment_length = int(segment_dual_head_metadata["max_segment_length"])
            adapter_input_dim = int(segment_dual_head_metadata.get("input_dim", clean.shape[-1]))
            architecture = str(segment_dual_head_metadata.get("architecture", "token_segment_dual_head_v1"))
            normalised_segments = _normalise_segments(text, surface, segments)[:max_segments]
            if architecture == "pooled_segment_dual_head_v1":
                segment_values = torch.zeros((1, max_segments, adapter_input_dim), dtype=torch.float32, device=device)
                segment_mask = torch.zeros((1, max_segments), dtype=torch.bool, device=device)
                segment_ids = torch.zeros((1, max_segments), dtype=torch.long, device=device)
                for seg_idx, (kind, value) in enumerate(normalised_segments):
                    kind_id = segment_names.index(kind) if kind in segment_names else 0
                    encoded_segment = tokenizer(
                        value,
                        return_tensors="pt",
                        truncation=True,
                        max_length=max_segment_length,
                        padding=True,
                    ).to(device)
                    segment_output = encoder(**encoded_segment)
                    token_mask = encoded_segment["attention_mask"].unsqueeze(-1).to(segment_output.last_hidden_state.dtype)
                    pooled = (segment_output.last_hidden_state * token_mask).sum(dim=1) / token_mask.sum(dim=1).clamp(min=1)
                    segment_values[:, seg_idx] = F.normalize(pooled.float(), p=2, dim=-1)
                    segment_mask[:, seg_idx] = True
                    segment_ids[:, seg_idx] = kind_id
            else:
                total_tokens = max_segments * max_segment_length
                segment_values = torch.zeros((1, total_tokens, adapter_input_dim), dtype=torch.float32, device=device)
                segment_mask = torch.zeros((1, total_tokens), dtype=torch.bool, device=device)
                segment_ids = torch.zeros((1, total_tokens), dtype=torch.long, device=device)
                for seg_idx, (kind, value) in enumerate(normalised_segments):
                    kind_id = segment_names.index(kind) if kind in segment_names else 0
                    encoded_segment = tokenizer(
                        value,
                        return_tensors="pt",
                        truncation=True,
                        max_length=max_segment_length,
                        padding="max_length",
                    ).to(device)
                    segment_output = encoder(**encoded_segment)
                    token_start = seg_idx * max_segment_length
                    token_end = token_start + max_segment_length
                    segment_values[:, token_start:token_end] = segment_output.last_hidden_state[:, :max_segment_length].float()
                    segment_mask[:, token_start:token_end] = encoded_segment["attention_mask"].bool()
                    segment_ids[:, token_start:token_end] = kind_id
            surface_id = torch.tensor([surface_names.index(surface) if surface in surface_names else 0], dtype=torch.long, device=device)
            safe_logits, active_logits = segment_dual_head(segment_values, segment_mask, segment_ids, surface_id)
            safe_score = float(torch.sigmoid(safe_logits)[0].detach().cpu())
            active_score = float(torch.sigmoid(active_logits)[0].detach().cpu())
            safe_threshold = float(segment_dual_head_metadata["safe_threshold"])
            active_threshold = float(segment_dual_head_metadata["active_threshold"])
            calibrated_score = None
            calibrated_threshold = None
            if segment_score_calibrator is not None and segment_score_calibrator_metadata.get("enabled"):
                calibrator_surfaces = list(segment_score_calibrator_metadata.get("surfaces", surface_names))
                surface_vec = torch.zeros((1, len(calibrator_surfaces)), dtype=torch.float32, device=device)
                if surface in calibrator_surfaces:
                    surface_vec[0, calibrator_surfaces.index(surface)] = 1.0
                safe_tensor = torch.tensor([[safe_score]], dtype=torch.float32, device=device)
                active_tensor = torch.tensor([[active_score]], dtype=torch.float32, device=device)
                lengths = torch.tensor(
                    [[float(len(text)), float(len(normalised_segments))]],
                    dtype=torch.float32,
                    device=device,
                )
                lengths = torch.log1p(lengths)
                feature = torch.cat(
                    [
                        safe_tensor,
                        active_tensor,
                        active_tensor - safe_tensor,
                        active_tensor * safe_tensor,
                        active_tensor * surface_vec,
                        safe_tensor * surface_vec,
                        surface_vec,
                        lengths,
                    ],
                    dim=1,
                )
                mean = torch.as_tensor(segment_score_calibrator_metadata["feature_mean"], dtype=torch.float32, device=device)
                std = torch.as_tensor(segment_score_calibrator_metadata["feature_std"], dtype=torch.float32, device=device)
                feature = (feature - mean) / std
                calibrated_score = float(torch.sigmoid(segment_score_calibrator(feature))[0].detach().cpu())
                calibrated_threshold = float(segment_score_calibrator_metadata["threshold"])
            dual_risk = calibrated_score if calibrated_score is not None else active_score
            decision_threshold = calibrated_threshold if calibrated_threshold is not None else active_threshold
            is_risky = bool(dual_risk >= decision_threshold)
            profile_selector_result: dict[str, Any] = {"enabled": False}
            if (
                segment_high_recall_dual_head is not None
                and segment_profile_selector is not None
                and segment_profile_selector_metadata.get("enabled")
            ):
                high_safe_logits, high_active_logits = segment_high_recall_dual_head(segment_values, segment_mask, segment_ids, surface_id)
                high_safe_score = float(torch.sigmoid(high_safe_logits)[0].detach().cpu())
                high_active_score = float(torch.sigmoid(high_active_logits)[0].detach().cpu())
                high_safe_threshold = float(segment_profile_selector_metadata["high_safe_threshold"])
                high_active_threshold = float(segment_profile_selector_metadata["high_active_threshold"])
                high_is_risky = high_active_score >= high_active_threshold
                selector_architecture = str(segment_profile_selector_metadata.get("architecture", "segment_role_profile_selector_v1"))
                if selector_architecture == "segment_role_profile_selector_v2":
                    if segment_profile_base_selector is None:
                        raise RuntimeError("segment role selector v2 requires a loaded base escalation selector")
                    base_feature_names = list(segment_profile_selector_metadata.get("base_feature_names", PROFILE_SELECTOR_FEATURE_NAMES))
                    base_feature_values = build_profile_selector_feature_values(
                        text=text,
                        surface=surface,
                        segments=normalised_segments,
                        strict_safe_score=safe_score,
                        strict_active_score=active_score,
                        strict_safe_threshold=safe_threshold,
                        strict_active_threshold=active_threshold,
                        high_safe_score=high_safe_score,
                        high_active_score=high_active_score,
                        high_safe_threshold=high_safe_threshold,
                        high_active_threshold=high_active_threshold,
                        feature_names=base_feature_names,
                    )
                    base_feature = torch.tensor([base_feature_values], dtype=torch.float32, device=device)
                    base_mean = torch.as_tensor(segment_profile_selector_metadata["base_feature_mean"], dtype=torch.float32, device=device)
                    base_std = torch.as_tensor(segment_profile_selector_metadata["base_feature_std"], dtype=torch.float32, device=device)
                    base_feature = (base_feature - base_mean) / base_std
                    escalation_score = float(torch.sigmoid(segment_profile_base_selector(base_feature))[0].detach().cpu())
                    escalation_threshold = float(segment_profile_selector_metadata["escalation_threshold"])

                    feature_names = list(segment_profile_selector_metadata.get("feature_names", PROFILE_SELECTOR_FEATURE_NAMES))
                    feature_values = build_profile_selector_feature_values(
                        text=text,
                        surface=surface,
                        segments=normalised_segments,
                        strict_safe_score=safe_score,
                        strict_active_score=active_score,
                        strict_safe_threshold=safe_threshold,
                        strict_active_threshold=active_threshold,
                        high_safe_score=high_safe_score,
                        high_active_score=high_active_score,
                        high_safe_threshold=high_safe_threshold,
                        high_active_threshold=high_active_threshold,
                        feature_names=feature_names,
                    )
                    feature = torch.tensor([feature_values], dtype=torch.float32, device=device)
                    mean = torch.as_tensor(segment_profile_selector_metadata["feature_mean"], dtype=torch.float32, device=device)
                    std = torch.as_tensor(segment_profile_selector_metadata["feature_std"], dtype=torch.float32, device=device)
                    feature = (feature - mean) / std
                    suppression_score = float(torch.sigmoid(segment_profile_selector(feature))[0].detach().cpu())
                    suppression_threshold = float(segment_profile_selector_metadata["suppression_threshold"])
                    selector_is_risky = escalation_score >= escalation_threshold
                    suppression_applied = suppression_score >= suppression_threshold
                    if selector_is_risky:
                        is_risky = True
                        dual_risk = max(dual_risk, escalation_score)
                    if suppression_applied:
                        is_risky = False
                        dual_risk = 0.0
                    profile_selector_result = {
                        "enabled": True,
                        "architecture": selector_architecture,
                        "score": round(escalation_score, 6),
                        "threshold": round(escalation_threshold, 6),
                        "is_risky": bool(selector_is_risky and not suppression_applied),
                        "decision_mode": segment_profile_selector_metadata.get("decision_mode"),
                        "selected_profile": (
                            "v5e_suppressed_strict"
                            if suppression_applied
                            else ("v5d_escalation" if selector_is_risky else "v5b_strict")
                        ),
                        "escalation_score": round(escalation_score, 6),
                        "escalation_threshold": round(escalation_threshold, 6),
                        "suppression_score": round(suppression_score, 6),
                        "suppression_threshold": round(suppression_threshold, 6),
                        "suppression_applied": bool(suppression_applied),
                        "high_recall_safe_frame_score": round(high_safe_score, 6),
                        "high_recall_active_intent_score": round(high_active_score, 6),
                        "high_recall_active_threshold": round(high_active_threshold, 6),
                        "high_recall_is_risky": bool(high_is_risky),
                        "role_escalation": bool(selector_is_risky and not high_is_risky and not suppression_applied),
                        "path": segment_profile_selector_metadata.get("path"),
                        "base_path": segment_profile_selector_metadata.get("base_path"),
                    }
                else:
                    feature_values = build_profile_selector_feature_values(
                        text=text,
                        surface=surface,
                        segments=normalised_segments,
                        strict_safe_score=safe_score,
                        strict_active_score=active_score,
                        strict_safe_threshold=safe_threshold,
                        strict_active_threshold=active_threshold,
                        high_safe_score=high_safe_score,
                        high_active_score=high_active_score,
                        high_safe_threshold=high_safe_threshold,
                        high_active_threshold=high_active_threshold,
                        feature_names=list(segment_profile_selector_metadata.get("feature_names", PROFILE_SELECTOR_FEATURE_NAMES)),
                    )
                    feature_names = list(segment_profile_selector_metadata.get("feature_names", PROFILE_SELECTOR_FEATURE_NAMES))
                    feature = torch.tensor([feature_values], dtype=torch.float32, device=device)
                    mean = torch.as_tensor(segment_profile_selector_metadata["feature_mean"], dtype=torch.float32, device=device)
                    std = torch.as_tensor(segment_profile_selector_metadata["feature_std"], dtype=torch.float32, device=device)
                    feature = (feature - mean) / std
                    selector_score = float(torch.sigmoid(segment_profile_selector(feature))[0].detach().cpu())
                    selector_threshold = float(segment_profile_selector_metadata["threshold"])
                    selector_is_risky = selector_score >= selector_threshold
                    if selector_is_risky:
                        is_risky = True
                        dual_risk = max(dual_risk, selector_score)
                    profile_selector_result = {
                        "enabled": True,
                        "architecture": selector_architecture,
                        "score": round(selector_score, 6),
                        "threshold": round(selector_threshold, 6),
                        "is_risky": bool(selector_is_risky),
                        "decision_mode": segment_profile_selector_metadata.get("decision_mode"),
                        "selected_profile": "v5c_light_high_recall" if selector_is_risky else "v5b_strict",
                        "high_recall_safe_frame_score": round(high_safe_score, 6),
                        "high_recall_active_intent_score": round(high_active_score, 6),
                        "high_recall_active_threshold": round(high_active_threshold, 6),
                        "high_recall_is_risky": bool(high_is_risky),
                        "role_escalation": bool(selector_is_risky and not high_is_risky),
                        "path": segment_profile_selector_metadata.get("path"),
                    }
            segment_dual_head_result = {
                "enabled": True,
                "safe_frame_score": round(safe_score, 6),
                "active_intent_score": round(active_score, 6),
                "dual_risk_score": round(dual_risk, 6),
                "safe_threshold": round(safe_threshold, 6),
                "active_threshold": round(active_threshold, 6),
                "calibrated_active_score": round(calibrated_score, 6) if calibrated_score is not None else None,
                "calibrated_active_threshold": round(calibrated_threshold, 6) if calibrated_threshold is not None else None,
                "raw_is_risky": bool(active_score >= active_threshold),
                "is_risky": is_risky,
                "is_safe_frame": bool(safe_score >= safe_threshold and not is_risky),
                "architecture": architecture,
                "profile_selector": profile_selector_result,
                "surface_score_calibrator": {
                    "enabled": bool(segment_score_calibrator_metadata.get("enabled")),
                    "path": segment_score_calibrator_metadata.get("path"),
                },
                "segment_count": len(normalised_segments),
                "segments": [{"kind": kind, "length": len(value)} for kind, value in normalised_segments],
                "path": segment_dual_head_metadata["path"],
            }
    probability = sum(probabilities) / len(probabilities)
    labels = ["qwen3_joint_online"]
    if segment_dual_head_result.get("enabled") and segment_dual_head_result.get("is_risky"):
        labels.append("embedding_segment_active_intent_risk")
        if (segment_dual_head_result.get("profile_selector") or {}).get("is_risky"):
            labels.append("embedding_segment_role_profile_selector_risk")
        if segment_dual_head_metadata.get("force_active_intent_floor", True):
            probability = max(probability, float(segment_dual_head_metadata.get("risk_floor", 1.0)))
    elif (segment_dual_head_result.get("profile_selector") or {}).get("suppression_applied"):
        labels.append("embedding_segment_role_profile_selector_suppressed")
    elif segment_dual_head_result.get("enabled") and segment_dual_head_result.get("is_safe_frame"):
        labels.append("embedding_segment_safe_frame")
    if probability >= threshold:
        labels.append("embedding_jailbreak_risk")
    return AnalysisResult(
        risk_score=probability,
        labels=labels,
        evidence=[
            f"qwen3_joint_probability={probability:.4f}",
            f"threshold={threshold:.4f}",
            *(
                [
                    f"segment_active_intent={segment_dual_head_result['active_intent_score']:.4f}",
                    f"segment_safe_frame={segment_dual_head_result['safe_frame_score']:.4f}",
                    *(
                        [
                            f"segment_role_selector={float((segment_dual_head_result.get('profile_selector') or {}).get('score', 0.0)):.4f}",
                            *(
                                [
                                    "segment_role_suppressed="
                                    f"{float((segment_dual_head_result.get('profile_selector') or {}).get('suppression_score', 0.0)):.4f}"
                                ]
                                if (segment_dual_head_result.get("profile_selector") or {}).get("suppression_applied")
                                else []
                            ),
                        ]
                        if (segment_dual_head_result.get("profile_selector") or {}).get("enabled")
                        else []
                    ),
                ]
                if segment_dual_head_result.get("enabled")
                else []
            ),
        ],
        metadata={
            "enabled": True,
            "probability": round(probability, 6),
            "probability_samples": [round(item, 6) for item in probabilities],
            "base_probability_samples": [round(item, 6) for item in base_probabilities],
            "threshold": threshold,
            "adapter": adapter_metadata,
            "avg_cosine_to_clean": round(sum(cosines) / len(cosines), 6),
            "latency_ms": round((perf_counter() - started) * 1000.0, 3),
            "profile": policy.get("profile"),
            "safe_frame_embedding_mlp": safe_frame_mlp_result,
            "segment_aware_dual_head": segment_dual_head_result,
        },
    )

from app.target_profiles import load_target_profiles


def list_target_catalog() -> list[dict]:
    catalog: list[dict] = []
    for profile in load_target_profiles():
        catalog.append(
            {
                "id": profile["id"],
                "label": profile["label"],
                "target_type": profile["target_type"],
                "access_mode": profile["access_mode"],
                "recommended_suite": profile["recommended_suite"],
                "why": profile["why"],
                "source_url": profile["source_url"],
            }
        )
    return catalog

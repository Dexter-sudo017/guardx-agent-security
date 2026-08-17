from abc import ABC, abstractmethod

from app.models import Message


class ModelAdapter(ABC):
    @abstractmethod
    def generate(self, message: str, history: list[Message], model: str) -> str:
        raise NotImplementedError


from pydantic import BaseModel


class ErrorResponse(BaseModel):
    detail: str


class SuccessResponse(BaseModel):
    message: str


class PaginationParams(BaseModel):
    skip: int = 0
    limit: int = 50

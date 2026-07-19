"""The single error type the API raises; the HTTP layer maps it to a status."""


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


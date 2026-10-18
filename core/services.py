class BaseService:

    @staticmethod
    def success(data=None, message="Success"):
        return {
            "success": True,
            "message": message,
            "data": data,
        }

    @staticmethod
    def error(message):
        return {
            "success": False,
            "message": message,
            "data": None,
        }
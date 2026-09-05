from backend.app import create_app
from backend.config import Config


app = create_app()


if __name__ == "__main__":
    print("=" * 60)
    print("AI PROMPT INJECTION TESTER")
    print("=" * 60)
    print(f"Server: http://{Config.HOST}:{Config.PORT}")
    print("Health: http://127.0.0.1:5000/api/health")
    print("=" * 60)

    app.run(
        host=Config.HOST,
        port=Config.PORT,
        debug=True
    )
from django.apps import AppConfig
from django.db import connection

class PM2Config(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'modules.pm2'

    def ready(self):
        # Dynamically ensure required PM2 management tables exist in MySQL
        try:
            with connection.cursor() as cursor:
                # Create pm2_apps table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS pm2_apps (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        userid_id INT NOT NULL,
                        domain_id INT NULL,
                        name VARCHAR(100) UNIQUE NOT NULL,
                        app_path VARCHAR(255) NOT NULL,
                        script_path VARCHAR(255) NOT NULL,
                        port INT NOT NULL,
                        env_variables TEXT NULL,
                        is_active TINYINT(1) NOT NULL DEFAULT 1,
                        created_at DATETIME NOT NULL,
                        FOREIGN KEY (userid_id) REFERENCES auth_user(id) ON DELETE CASCADE
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                """)
                print("[PM2Manager] Database initialization completed successfully.")
        except Exception as e:
            print(f"[PM2Manager] Database initialization warning: {e}")

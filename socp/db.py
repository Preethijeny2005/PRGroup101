import aiomysql
import asyncio
import time
import uuid

DB_CONFIG = {
    "host": "127.0.0.1",
    "port": 3306,
    "user": "chat_user",
    "password": "yourpassword",
    "db": "chatdb"
}

# --- Full schema without foreign key constraints ---
SCHEMA_SQL = [
    """
    CREATE TABLE IF NOT EXISTS users (
        user_id CHAR(36) PRIMARY KEY,
        pubkey TEXT NOT NULL,
        privkey_store TEXT NOT NULL,
        pake_password TEXT NOT NULL,
        display_name CHAR(36) NOT NULL,
        version INT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS public_channel (
        group_id CHAR(36) PRIMARY KEY,
        creator_id CHAR(36) NOT NULL,
        created_at BIGINT NOT NULL,
        meta JSON,
        version INT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS public_members (
        group_id CHAR(36) NOT NULL,
        name CHAR(36) NOT NULL,
        member_id CHAR(36) NOT NULL,
        role ENUM('owner','admin','member') DEFAULT 'member',
        wrapped_key TEXT NOT NULL,
        added_at BIGINT NOT NULL,
        PRIMARY KEY (group_id, member_id)
    );
    """
]

async def init_db():
    conn = await aiomysql.connect(**DB_CONFIG)
    async with conn.cursor() as cur:
        for stmt in SCHEMA_SQL:
            if stmt.strip():
                try:
                    await cur.execute(stmt)
                except Exception as e:
                    print(f"Warning: {e}")

        # Ensure "public" group exists
        await cur.execute("""
            INSERT INTO public_channel (group_id, creator_id, created_at, meta, version)
            VALUES ('public', 'system', %s, JSON_OBJECT(), 1)
            ON DUPLICATE KEY UPDATE group_id=group_id;
        """, (int(time.time()),))
    await conn.commit()
    conn.close()


async def add_user(pubkey, privkey_store, pake_password, display_name):
    user_id = str(uuid.uuid4())
    conn = await aiomysql.connect(**DB_CONFIG)
    async with conn.cursor() as cur:
        await cur.execute("""
            INSERT INTO users (user_id, pubkey, privkey_store, pake_password, display_name, version)
            VALUES (%s, %s, %s, %s, %s, 1)
        """, (user_id, pubkey, privkey_store, pake_password, display_name))
    await conn.commit()
    conn.close()
    return user_id


async def join_group(user_id, display_name, group_id="public", role="member", wrapped_key="encrypted_key_blob"):
    conn = await aiomysql.connect(**DB_CONFIG)
    async with conn.cursor() as cur:
        await cur.execute("""
            INSERT INTO public_members (group_id, name, member_id, role, wrapped_key, added_at)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE added_at=VALUES(added_at);
        """, (group_id, display_name, user_id, role, wrapped_key, int(time.time())))
    await conn.commit()
    conn.close()


# --- Test script ---
async def main():
    await init_db()

if __name__ == "__main__":
    asyncio.run(main())

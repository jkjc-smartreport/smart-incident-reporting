from werkzeug.security import generate_password_hash

for role, password in [
    ("BFP", "bfp123"),
    ("PNP", "pnp123"),
    ("CDRRMO", "cdrrmo123"),
]:
    hashed = generate_password_hash(password)
    print(f"{role} → {hashed}")

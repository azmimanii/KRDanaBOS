from sqlalchemy import create_engine

db_user = "root" # ex : root
db_password = ""
db_host = "34.101.106.57" # ex : localhost
db_port = 3306 # ex :3306
db_database = "danabos" #ex : db_afkar
db_sslmode = True

# ini klo pake mysql
db_engine = f"mysql+pymysql://{db_user}:{db_password}@{db_host}:{db_port}/{db_database}"

engine = create_engine(db_engine)
conn = engine.connect()
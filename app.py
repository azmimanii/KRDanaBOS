from flask import Flask, render_template, request, jsonify, redirect, session
from route.user import blueprint as user_blueprint
from services.database_Service import conn as cur
from dotenv import load_dotenv
from decimal import Decimal
from datetime import datetime, timedelta
from flask_mail import Mail, Message
from sqlalchemy import text
import bcrypt
import jwt
import secrets
import re
import json

load_dotenv()
app = Flask(__name__)

app.config["SECRET_KEY"] = "secret"
app.config["MAIL_PORT"] = 587
app.config["MAIL_SERVER"] = "imap.gmail.com"
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_DEFAULT_SENDER"] = "18220030@std.stei.itb.ac.id"
app.config["MAIL_USERNAME"] = "18220030@std.stei.itb.ac.id"
app.config["MAIL_PASSWORD"] = "zvdomkdzzblvxnir"

mail = Mail(app)

app.register_blueprint(user_blueprint)

@app.route('/')
def hello_world():  # put application's code here
    return 'Hello! This is Ami!'

# Authentication

def otpHandler(data):
  otp = secrets.token_hex(3)
  session["otp"] = otp  # Store the OTP in the session
  msg = Message("Your OTP, Happy Coding!", recipients=[data['email']])
  msg.body = f"Your OTP is {otp}"
  mail.send(msg)

  return "Successfully sending OTP request! Please check your email!"

def checkUserAvailable(cur, data):
    result = cur.execute('SELECT * FROM user WHERE email=%s', (data['email'],))
    return result.rowcount > 0

def checkToken(bearer):
  try:
    token = bearer.split()[1]
    decodedToken = jwt.decode(token, "secret", algorithms=['HS256'])
    date_str = decodedToken['exp_date']
    tokenDate = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S")
    if (tokenDate < datetime.now()):
      raise 

    return True
  except:
    print(tokenDate)
    print(date_str)
    return False

def checkOTP(otp):
  sessionOtp = session.get('otp')
  if (otp == sessionOtp):
    try:
      createUser()
    except:
      return "Failed to create user", 400

    session.clear()
    return "Success creating new account!", 201

  else: 
    return "Wrong OTP!", 200

def validEmail(email):
    regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    if re.match(regex, email):
        return True
    return False

def createUser():
  data = session.get('user_cred')

  encodedPass = encodeStr(data['password'])

  cur.execute('INSERT INTO user(email, password) VALUES (%s, %s) ', (data['email'], encodedPass))

@app.route('/sign-up', methods=['GET', 'POST'])
def signUp():
  json_data = request.json

  otp = request.args.get('otp')
  if (otp):
    return checkOTP(otp)

  data = {
    'email': json_data['email'],
    'password': json_data['password']
    }
  session['user_cred'] = data

  if not validEmail(data['email']):
    return "Please enter a valid Email", 401

  if checkUserAvailable(cur, data):
    return "Your email or Password is already used!", 401

  else:
    try:
      res = otpHandler(data)
    except:
      return "Failed to send OTP! Please retry!", 400
    return res, 200

@app.route('/log-in', methods=['GET', 'POST'])
def logIn():
    json_data = request.json

    data = {
        "email": json_data['email'],
        "password": json_data['password'],
    }

    for user in cur.execute(' SELECT * FROM user WHERE email=%s LIMIT 1', (data['email'],)):
        if (verifyUser(data['password'], user['password'])):
            date = datetime.now() + timedelta(days=7)
            date_str = date.strftime("%Y-%m-%dT%H:%M:%S")
            token = jwt.encode({'exp_date' : date_str}, "secret")
            return jsonify(
                {
                'message': 'Please save this token and use it to access our provided API! This token will last for 7 Days',
                'token' : token
                }), 201
    return "No available email! Please sign in", 404

# Main App

@app.route("/getKr", methods=["GET"])
def getKr():
  auth_header = request.args.get("Authorization")
  
  valid = checkToken(auth_header)

  if not valid:
    return "Token not valid", 404

  rows = []
  for rinfo in cur.execute("SELECT * FROM kondisiruangan;"):
    rows.append(rinfo)
  
  room_info = []  
  for p in rows:
    room_info.append({
      "Id" : p[0],
      "Kecamatan" : p[1],
      "Sekolah" : p[2],
      "Baik" : str(p[3]),
      "Rusak Ringan" : str(p[4]),
      "Rusak Sedang" : str(p[5]),
      "Rusak Berat" : str(p[6]),
      "Jumlah Ruangan" : str(p[7])
    })

  return jsonify(room_info)

@app.route("/getKrByID", methods=["GET"])
def getKrByID():
  ID = request.args.get("ID")
  auth_header = request.args.get("Authorization")
  
  valid = checkToken(auth_header)

  if not valid:
    return "Token not valid", 404

  rows = []
  for rinfo in cur.execute(text("SELECT * FROM kondisiruangan WHERE ID =:rid"), {"rid": ID}):
    rows.append(rinfo)
  
  room_info = []  
  for p in rows:
    room_info.append({
      "Id" : p[0],
      "Kecamatan" : p[1],
      "Sekolah" : p[2],
      "Baik" : str(p[3]),
      "Rusak Ringan" : str(p[4]),
      "Rusak Sedang" : str(p[5]),
      "Rusak Berat" : str(p[6]),
      "Jumlah Ruangan" : str(p[7])
    })

  return jsonify(room_info)  

@app.route("/getKrByName", methods=["GET"])
def getKrByName():
  name = request.args.get("name")
  auth_header = request.args.get("Authorization")
  
  valid = checkToken(auth_header)

  if not valid:
    return "Token not valid", 404

  rows = []
  for rinfo in cur.execute(text("SELECT * FROM kondisiruangan WHERE Nama_Sekolah LIKE :rname"), {"rname": f"%{name}%"}):
    rows.append(rinfo)
  
  room_info = []  
  for p in rows:
    room_info.append({
      "Id" : p[0],
      "Kecamatan" : p[1],
      "Sekolah" : p[2],
      "Baik" : str(p[3]),
      "Rusak Ringan" : str(p[4]),
      "Rusak Sedang" : str(p[5]),
      "Rusak Berat" : str(p[6]),
      "Jumlah Ruangan" : str(p[7])
    })

  return jsonify(room_info)  

@app.route("/deleteKr", methods=["DELETE"])
def deleteKr():
  ID = request.args.get('ID')
  auth_header = request.args.get("Authorization")

  valid = checkToken(auth_header)

  if not valid:
    return "Token not valid", 404
  
  cur.execute("DELETE FROM kondisiruangan WHERE ID = %s", (ID,))
  return f"Delete kondisi ruangan success! [Id = {ID}]"

@app.route("/updateKr", methods=["PUT"])
def updateKr():
  ID = request.args.get('ID')
  auth_header = request.args.get("Authorization")

  valid = checkToken(auth_header)

  if not valid:
    return "Token not valid", 404


  body = request.json

  payload = {
    "ID" : ID,
    "nama_kecamatan" : body["nama_kecamatan"],
    "nama_sekolah" : body["nama_sekolah"],
    "baik" : body["baik"],
    "rusak_ringan" : body["rusak_ringan"],
    "rusak_sedang" : body["rusak_sedang"],
    "rusak_berat" : body["rusak_berat"]
  }
  
  jumlah_ruangan = int(payload["baik"]) + int(payload["rusak_ringan"]) + int(payload["rusak_sedang"]) + int(payload["rusak_berat"])


  cur.execute("UPDATE kondisiruangan SET Nama_Kecamatan = %s, Nama_Sekolah = %s, Baik = %s, Rusak_Ringan = %s, Rusak_Sedang = %s, Rusak_Berat = %s, Jumlah_Ruangan = %s WHERE ID = %s", (payload["nama_kecamatan"], payload["nama_sekolah"], payload["baik"], payload["rusak_ringan"], payload["rusak_sedang"], payload["rusak_berat"], jumlah_ruangan, payload["ID"]))
  return jsonify(payload)

@app.route("/writeKr", methods=["POST"])
def writeKr():
  auth_header = request.args.get("Authorization")

  valid = checkToken(auth_header)

  if not valid:
    return "Token not valid", 404
  
  body = request.json

  payload = {
    "nama_kecamatan" : body["nama_kecamatan"],
    "nama_sekolah" : body["nama_sekolah"],
    "baik" : body["baik"],
    "rusak_ringan" : body["rusak_ringan"],
    "rusak_sedang" : body["rusak_sedang"],
    "rusak_berat" : body["rusak_berat"],
  }

  jumlah_ruangan = int(payload["baik"]) + int(payload["rusak_ringan"]) + int(payload["rusak_sedang"]) + int(payload["rusak_berat"])
  
  cur.execute("INSERT INTO kondisiruangan (Nama_Kecamatan, Nama_Sekolah, Baik, Rusak_Ringan, Rusak_Sedang, Rusak_Berat, Jumlah_Ruangan) VALUES (%s, %s, %s, %s, %s, %s, %s)", (payload["nama_kecamatan"], payload["nama_sekolah"], payload["baik"], payload["rusak_ringan"], payload["rusak_sedang"], payload["rusak_berat"], jumlah_ruangan))
  return jsonify(payload)

@app.route("/calculate-kr", methods=["GET"])

def calculateKR(id: int):
  auth_header = request.args.get("Authorization")
  ID = request.args.get("ID")

  valid = checkToken(auth_header)

  if not valid:
    return "Token not valid", 404

  rows = []
  for pinfo in cur.execute("SELECT * FROM `datasetplayer` WHERE ID = %s", (ID,)):
    rows.append(pinfo)

  room_info = []
  for p in rows:
    rumus = Decimal(4) * p[3] + Decimal(3) * p[4] + Decimal(2) * p[5] + Decimal(1) * p[6]
    nilai = (rumus/(Decimal(4)* p[7]))*Decimal(100)
    hasil = str(nilai) + "%"
    room_info.append({
      "ID" : p[0],
      "Nama Sekolah" : p[2],
      "Tingkat Kelayakan Infrastruktur" : hasil
    })
  return jsonify(room_info)



#     response = {"ID Sekolah" :rinfo, "Persentase Kelayakan" : persentaseKelayakan}
#     return jsonify(response)

# @app.route("/level-kr", methods=["GET"])
# def levelKR(user):
#   auth_header = request.args.get("Authorization")

#   valid = checkToken(auth_header)

#   if not valid:
#     return "Token not valid", 404
    
#   if request.method == "GET":
#       cur = conn.cursor()
#       cur.execute(
#       f"SELECT Persentase_Kelayakan FROM kondisiruangan")
#       data = cur.fetchall()

#       for row in data:
#           if row[1]>=90:
#               return 'Sangat Baik'
#           elif row[1]<90 and row[1]>=75:
#               return 'Baik'
#           elif row[1]<75 and row[1]>=60:
#               return 'Sedang'
#           elif row[1]<60 and row[1]>=50:
#               return 'Buruk'
#           else:
#               return 'Sangat Buruk'


key = "7eSEw7FDi6FHwBS7WyeVlrSjzWhGT4NW"

def encodeStr(ePass):
  hashed_password = bcrypt.hashpw((key+ePass).encode("utf-8"), bcrypt.gensalt())
  return hashed_password

def verifyUser(ePass, cPass):
  return bcrypt.checkpw((key+ePass).encode("utf-8"), cPass.encode("utf-8"))

if __name__ == '__main__':
    app.run()

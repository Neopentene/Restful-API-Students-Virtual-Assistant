from flask import Flask, request, Response
from flask import jsonify
from flask_cors import CORS, cross_origin
from random import choice
from string import ascii_uppercase
from cryptography.fernet import Fernet
from mysql.connector import pooling
import jwt
import time
import datetime
import hashlib
import bcrypt
import mysql.connector
from werkzeug.datastructures import ImmutableMultiDict
import codecs
import os

app = Flask(__name__)
CORS(app)
CORS(app, resources={r"/*": {"origins": "*"}})
#app.config['CORS_HEADERS'] = 'Content-Type'

"""
Response Format
{
"success": Value,
"error": Value,
"token": Value,
"data": {Value}
}

Token Format
{
"userData": Value,
"issuedOn": Value
}

"""

key = "2fb9b09e8c1020c5953932371c93974c22c35e473a420305d0075c910c483ca9"
encryptionKey = b'4XDS_8RaXzygrSg93FwlFpFTA8tDk8wrCItovnn_i1I='
pepper = b'$2b$12$zkKTQgjwyoUWdcGRrKhB9e'
algorithm = "HS256"
#HSDA/HSLA256
saltkey = b'xmEJMgUZXDiOM55jeGSTJjOC-jXsv3iLCs_vbl3L2co='

expirationTime = 600
tokenExpired = "Token has expired"
tokenInvalid = "Token is invalid"
tokenFound = "Token was found"
tokenNotFound = "Token was not found"
tokenFoundHead = "Token was found in header"
userName="Admin"
email = "Admin"
fernet = Fernet(encryptionKey)
saltFernet = Fernet(saltkey)
dbHost = "localhost"
dbPort = 3306
dbUser = "root"
dbPassword = ""
dbName = "student_virtual_assistant"
imagePath = "D:/College Work/Mini-project/Voice/Project/Admin Backend/faculty_images/"

#%%

class DbManager():
    
    def __init__(self, host: str, port: int, user: str, password: str, database: str):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.database = database
        self.dbPool = pooling.MySQLConnectionPool(
                                                    pool_name = "virtual_assistant_pool",
                                                    pool_size = 5,
                                                    pool_reset_session= True,
                                                    host = self.host,
                                                    database = self.database,
                                                    user = self.user,
                                                    password = self.password,
                                                    port = self.port
                                                )
    
    def initializeDB(self):
        self.db = self.dbPool.get_connection()
        return self
        
    def getConnection(self):
        if self.db is None:
            self.initializeDB()
            return True
        
        if not self.db.is_connected():
            self.initializeDB()
            return True
        return True
        
    def getAllFaculties(self):
        if self.getConnection():
            with self.db.cursor() as cursor:
                cursor.execute("SELECT faculty_name, faculty_email, pswd, pswd_ran FROM faculty")
                result = cursor.fetchall()
            return result
        return None
    
    def getFacultyDetails(self, userName: str, email: str):
        if self.getConnection():
            query = 'SELECT * FROM faculty_detail WHERE faculty_id IN  (SELECT faculty_id FROM faculty WHERE faculty_name = "' + (userName if userName is not None else '') + '" OR faculty_email = "' + (email if email is not None else '') + '")'
            with self.db.cursor() as cursor:            
                cursor.execute(query)
                result = cursor.fetchone()
            return result
        return None
    
    def getAllFacultyUsernames(self):
        if self.getConnection():
            query = 'SELECT faculty_name FROM faculty'
            with self.db.cursor() as cursor:            
                cursor.execute(query)
                result = cursor.fetchall()
            return result
        return None
    
    def getAllFacultyEmails(self):
        if self.getConnection():
            query = 'SELECT faculty_email FROM faculty'
            with self.db.cursor() as cursor:            
                cursor.execute(query)
                result = cursor.fetchall()
            return result
        return None
    
    def getAllFacultyUsernamesAndEmails(self):
        if self.getConnection():
            query = 'SELECT faculty_name, faculty_email FROM faculty'
            with self.db.cursor() as cursor:            
                cursor.execute(query)
                result = cursor.fetchall()
            return result
        return None
    
    def createNewFacultyUser(self, userName: str, email: str, password: str, salt: str):
        assert userName is not None and email is not None and password is not None
        if self.getConnection():
            secureQuery = True
            for data in self.getAllFacultyUsernamesAndEmails():
                if userName in data or email in data:
                    secureQuery = False
            if secureQuery:
                query = 'INSERT INTO faculty VALUES (' + str(self.__autoIncrementValue()) + ', "' + userName +'", "' + email + '", "' + password + '", "' + salt + '")'
                with self.db.cursor() as cursor:            
                    cursor.execute(query)
                return self
        return None
    
    def __getId(self, userName: str, email: str):
        if self.getConnection():
            query = 'SELECT faculty_id FROM faculty WHERE faculty_name="' + userName + '" OR faculty_email="' + email + '"'
            with self.db.cursor() as cursor:            
                cursor.execute(query)
                result = cursor.fetchone()
            return result[0]
        return None
    
    def addFacultyDetails(self, userName: str, email: str, firstName: str, lastName: str, designation: str, department: str, address = "", imageUrl = ""):
        assert firstName is not None and lastName is not None and designation is not None and department is not None
        assert userName is not None and userName != '' or email is not None and email != ''
        if self.getConnection():
            address = address if address is not None else ''
            imageUrl = imageUrl.replace("\\", "/") if imageUrl is not None else ''
            facultyId = self.__getId(userName, email)
            query = 'INSERT INTO faculty_detail VALUES'
            values = '("' + str(facultyId) + '", "' + designation + '", "' + firstName + ' ' + lastName + '", "' + address + '", "' + department + '", "' + imageUrl + '")'
            with self.db.cursor() as cursor:            
                cursor.execute(query + values)
            return self
        return None
    
    def removeFacultyContacts(self, userName: str, email: str):
        if self.getConnection():
            facultyId = self.__getId(userName, email)
            query = 'DELETE FROM `faculty_contact` WHERE faculty_id = ' + str(facultyId)
            with self.db.cursor() as cursor:            
                cursor.execute(query)
            return self
        return None

    def addFacultyContacts(self, userName: str, email: str, contacts = []):
        if self.getConnection():
            facultyId = self.__getId(userName, email)
            for contact in contacts:
                query = 'INSERT INTO faculty_contact VALUES'
                values = '("' + facultyId + '", "' + contact + '")'
                with self.db.cursor() as cursor:            
                    cursor.execute(query + values)
            return self
        return None
    
    def __autoIncrementValue(self):
        if self.getConnection():
            query = 'SELECT MAX(faculty_id) FROM faculty'
            with self.db.cursor() as cursor:            
                cursor.execute(query)
                value = cursor.fetchone()[0]
            return (value + 1)
        return None
    
    def getAllDepartment(self):
        if self.getConnection():
            query = 'SELECT * FROM department'
            with self.db.cursor() as cursor:            
                cursor.execute(query)
                result = cursor.fetchall()
            return result
        return None
    
    def getFacultyContact(self, userName: str, email: str):
        if self.getConnection():
            facultyId = self.__getId(userName, email)
            query = 'SELECT contact FROM faculty_contact WHERE faculty_id=' + str(facultyId)
            with self.db.cursor() as cursor:            
                cursor.execute(query)
                result = cursor.fetchall()
            filteredResult = {}
            count = 0
            for data in result:
                filteredResult[str(count)] = data[0]
                count += 1
            return filteredResult
        return None
    
    def getAllDays(self):
        if self.getConnection():
            query = 'SELECT * FROM day'
            with self.db.cursor() as cursor:            
                cursor.execute(query)
                result = cursor.fetchall()
            return result
        return None
    
    def getAllFacultyDetails(self):
        if self.getConnection():
            query = 'SELECT * FROM faculty_detail'
            with self.db.cursor() as cursor:            
                cursor.execute(query)
                result = cursor.fetchall()
            return result
        return None
    
    def updateFacultyDetails(self, userName: str, email: str, firstName: str, lastName: str, designation: str, department: str, address = "", imageUrl = "", contacts = []):
        if self.getConnection():
            facultyId = self.__getId(userName, email)
            query = f'UPDATE `faculty_detail` SET `designation`="{designation}",`faculty_name`="{(firstName + " " + lastName).strip()}",`address`="{address}",`dept_name`="{department}",`faculty_image_url`="{imageUrl}" WHERE faculty_id = {str(facultyId)}'
            with self.db.cursor() as cursor:            
                cursor.execute(query)
            self.addFacultyContacts(userName, email, contacts)
            return self
        return None
        
    
    def commit(self):
        self.db.commit()
        return self
    
    def commitClose(self):
        self.db.commit()
        self.db.close()
        return self




#%%

def getCurrentTimeStamp():
    return datetime.datetime.now().timestamp()

def getPasswordHash(password: str, salt: str):
    return bcrypt.hashpw(password.encode("utf-8") + pepper, saltFernet.decrypt(salt.encode("utf-8"))).decode("utf-8")
    

def generatePassword(password: str):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8") + pepper, salt).decode("utf-8"), saltFernet.encrypt(salt).decode("utf-8")

def getNoise():
    Noise = ''.join(choice(ascii_uppercase) for i in range(12))
    return Noise

def isJwtTimeValid(timeStamp: float):
    currentDate = datetime.datetime.now().timestamp()
    if (currentDate - timeStamp) < expirationTime:
        return True
    return False
    
def createJwtToken(data):
    return fernet.encrypt(codecs.encode(jwt.encode(data, key, algorithm=algorithm), "utf-8")).decode("utf-8")
     

def checkForToken(request):
    try:
        if request.values["token"] is not None and request.values["token"] != '':
            return tokenFound
    except Exception:
        try:
            if request.headers["token"] is not None and request.headers["token"] != '':
                return tokenFoundHead
            return tokenNotFound
        except Exception:
            return tokenNotFound
        return tokenNotFound

def validateJwt(token: str):
    try:
        tokenData = jwt.decode(fernet.decrypt(codecs.encode(token, "utf-8")), key, algorithms=algorithm)
        if tokenData["issuedOn"] != None:
            if isJwtTimeValid(float(tokenData["issuedOn"])):
                tokenData["userData"]["Noise"] = getNoise()
                return {"userData": ImmutableMultiDict(tokenData["userData"]), "issuedOn": getCurrentTimeStamp()}
            return tokenExpired
    except Exception:
        return tokenInvalid
    
def filterUserValidation(userNameFlag: bool, emailFlag: bool, passwordFlag: bool):
    if userNameFlag == True or emailFlag == True:
        if not passwordFlag == True:
            errorMessage = "Password Incorrect"
        else:
            return True, "None"
    else:
        errorMessage = "Username or Email is incorrect"
    return False, errorMessage
    
#%%

def validateUser(userData):
    
    db = DbManager(dbHost, dbPort, dbUser, dbPassword, dbName).initializeDB()

    if not db.db.is_connected():
        raise Exception("Unable to access database")
    
    passwordFlag = False
    emailFlag = False
    userNameFlag = False

    faculty = db.getAllFaculties()
    
    print(type(faculty))
        
    for data in faculty:
            if userData["userName"] in data:
                userNameFlag = True
                if getPasswordHash(userData["password"], data[3]) == data[2]:
                    passwordFlag = True
                    userData = {"userData": userData, "issuedOn": datetime.datetime.now().timestamp()}
                break
    
            elif userData["email"] in data:
                emailFlag = True
                if getPasswordHash(userData["password"], data[3]) == data[2]:
                    passwordFlag = True
                    userData = {"userData": userData, "issuedOn": datetime.datetime.now().timestamp()}
                break
    
    return filterUserValidation(userNameFlag, emailFlag, passwordFlag)

def getDefaultUserDataFormat():
    return {"userData": {"userName": None, "email": None, "password": None, "Noise": getNoise()}, "issuedOn": None}


def completeJwtUserValidation(request):
    userDataFormat = getDefaultUserDataFormat()
    tokenCheck = checkForToken(request)
    errorMessage = "None"
    success = False
    
    if tokenCheck == tokenFound or tokenCheck == tokenFoundHead:
        if tokenCheck == tokenFoundHead:
            tokenDataValidation = validateJwt(request.headers["token"])
        else: 
            tokenDataValidation = validateJwt(request.values["token"])
        
        if tokenDataValidation != tokenExpired and tokenDataValidation != tokenInvalid:
            userData = tokenDataValidation["userData"]
            success, errorMessage = validateUser(userData)
            
            if success:
                userDataFormat["userData"] = userData
                userDataFormat["issuedOn"] = getCurrentTimeStamp()
                return success, errorMessage, userDataFormat
        else:
            errorMessage = tokenDataValidation
            return success, errorMessage, userDataFormat
    else:
        errorMessage = tokenCheck
        return success, errorMessage, userDataFormat
    
def responseJwtFormat(success: bool, errorMessage: str, token: str):
    return {"success": success, "error": errorMessage, "token": token}

def getImageInBase64(path: str):
    if path is None or path == "None" or path == "":
        return ''

    with open(path, 'rb') as file:
        imageData = codecs.encode(file.read(), "base64")
    return imageData.decode("utf-8")

def shortFormatAllFacultyDetails(data: tuple):
    return  {"name": data[2], "designation": data[4], "department": data[1]}
    

def userDetailsFormat(data: tuple, contact={}, decodeImg=True):
    return {"name": data[2], "designation": data[1], "department": data[4], "address": data[3], "image": getImageInBase64(data[5]) if decodeImg else data[5], "contacts": contact}
    

#%%

@app.after_request
def after_request(response):
    #response.headers.add('Access-Control-Allow-Origin', '*')
    
    #Access-Control-Request-Headers
    response.headers.add('Access-Control-Request-Headers', 'Content-Type, application/x-www-form-urlencoded')
        
    #Access-Control-Allow-Methods
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')

    return response
        

@app.route('/')
@cross_origin()
def index():
    db = DbManager(dbHost, dbPort, dbUser, dbPassword, dbName).initializeDB()

    if not db.db.is_connected():
        raise Exception("Unable to access database")
        
    serverConnection = "Server Up"
    if db == None:
        serverConnection = "Server Down"
    
    print(request.json)
        
    return f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta http-equiv="X-UA-Compatible" content="IE=edge">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Document</title>
            </head>
            <body>
                <h2>{serverConnection}</h2>
            </body>
            </html>
            """
            
@app.route('/faculty/login', methods=['POST', 'GET'])
@cross_origin()
def validate():
    db = DbManager(dbHost, dbPort, dbUser, dbPassword, dbName).initializeDB()

    if not db.db.is_connected():
        raise Exception("Unable to access database")
    
    success = False
    errorMessage = "None"
    userData = getDefaultUserDataFormat()
    
    try: 
        if request.values is not None and len(request.values) > 0:
            token = request.values["token"] if request.values["token"] is not None and request.values["token"] != '' and request.values["token"] != 'null' else None
            
            if token is not None:
                token = validateJwt(token)
                
                if token != tokenExpired and token != tokenInvalid:
                    userData = token
                
                else:
                    if token != tokenInvalid and request.values["userName"] is not None and request.values["userName"] != '' or request.values["email"] is not None and request.values["email"] != '':
                        userData["userData"] = { "userName": request.values["userName"], "email": request.values["email"], "password": request.values["password"]}
                        
                    else:
                        errorMessage = token
                        return responseJwtFormat(success, errorMessage, None)
                
            elif request.values["userName"] is not None and request.values["userName"] != '' or request.values["email"] is not None and request.values["email"] != '':
                
                userData["userData"] = { "userName": request.values["userName"], "email": request.values["email"], "password": request.values["password"]}
                
            else:
                errorMessage = "Invalid call to server"
                return responseJwtFormat(success, errorMessage, None)
        else:
            errorMessage = "Invalid call to server"
            return responseJwtFormat(success, errorMessage, None)
    except Exception:
        try:
            try:    
                userData["userData"] = { "userName": request.values["userName"], "email": '', "password": request.values["password"]}
            except Exception:
                userData["userData"] = { "userName": '', "email": request.values["email"], "password": request.values["password"]}
            
            if userData["userData"]["userName"] == '' and userData["userData"]["email"] == '' or userData["userData"]["password"] == '':
                errorMessage = "Invalid form details"
                return responseJwtFormat(success, errorMessage, None)
            
        except Exception:
            errorMessage = "Invalid request data"
            return responseJwtFormat(success, errorMessage, None)
    
    #userDataSet has been set...
    
    
    success, errorMessage = validateUser(userData["userData"])
        
    if not success:
        return responseJwtFormat(success, errorMessage, None)
    else:
        userData["issuedOn"] = getCurrentTimeStamp()

    return responseJwtFormat(success, errorMessage, createJwtToken(userData))

#%%

@app.route('/faculty/create', methods=['PUT'])
@cross_origin()
def createNewFaculty():
    db = DbManager(dbHost, dbPort, dbUser, dbPassword, dbName).initializeDB()

    if not db.db.is_connected():
        raise Exception("Unable to access database")
    
    success, errorMessage, userDataFormat = completeJwtUserValidation(request)
    
    if not success:
        return responseJwtFormat(success, errorMessage, None)
        
    try:
        try:
            userName = request.values["userName"]
            email = request.values["email"]
            password, salt = generatePassword(request.values["password"])
            firstName = request.values["firstName"]
            lastName = request.values["lastName"]
            designation = request.values["designation"]
            department = request.values["department"]
            address = request.values["address"] if request.values["address"] is not None else ''
            image = request.values["imageData"] if request.values["imageData"] is not None else ''
            imageExtension = request.values["imageExtension"] if request.values["imageExtension"] is not None else 'png'
        
        except Exception as e:
            success = False
            errorMessage = "Invalid form data"
            raise Exception(errorMessage)
        
        for name in db.getAllFacultyUsernames():
            if userName in name:
                success = False
                errorMessage = "Username is taken"
                raise Exception(errorMessage)
            
        for emailAddresses in db.getAllFacultyEmails():
            if email in emailAddresses:
                success = False
                errorMessage = "Email has been used"
                raise Exception(errorMessage)
        
        try:
            imageUrl = imagePath + firstName + "_" + lastName + "_" + getNoise() + "." + imageExtension
            with open(imageUrl, 'wb') as file:
                image = image.replace(" ", "+")
                file.write(codecs.decode(image.encode("utf-8"), "base64"))
        except Exception as e:
            imageUrl = ''
            errorMessage = "No image was found"
            print(e)
        
        try:
            db.createNewFacultyUser(userName, email, password, salt)
            db.addFacultyDetails(userName, email, firstName, lastName, designation, department, address, imageUrl)

        except Exception as e:
            success = False
            errorMessage = "Data mismatch please check your input fields"
            return responseJwtFormat(success, errorMessage, None)
        
        db.commit()
        
    except Exception as e:
        print(e)
        return responseJwtFormat(success, errorMessage, createJwtToken(userDataFormat))
    
    return responseJwtFormat(success, errorMessage, createJwtToken(userDataFormat))
    

@app.route('/faculty/details', methods=['GET'])
@cross_origin()
def getDetails():
    db = DbManager(dbHost, dbPort, dbUser, dbPassword, dbName).initializeDB()

    if not db.db.is_connected():
        raise Exception("Unable to access database")
        
    success, errorMessage, userDataFormat = completeJwtUserValidation(request)
        
    if not success:
        return responseJwtFormat(success, errorMessage, None)
        
    try:
        userName = userDataFormat["userData"]["userName"]
        email = userDataFormat["userData"]["email"]
        
        
        try:
            data = db.getFacultyDetails(userName, email)
            data = userDetailsFormat(data)
            data["contacts"] = db.getFacultyContact(userName, email)

        except:
            success = False
            errorMessage = "Some error occurred while fetching image"
            return responseJwtFormat(success, errorMessage, createJwtToken(userDataFormat))
    except:
        success = False
        errorMessage = "Error in user details"
        return responseJwtFormat(success, errorMessage, None)
    
    parsed = responseJwtFormat(success, errorMessage, createJwtToken(userDataFormat))
    parsed["data"] = data
    
    return parsed

    
@app.route('/faculty/all', methods=['GET'])
@cross_origin()
def getAllFaculties():
    db = DbManager(dbHost, dbPort, dbUser, dbPassword, dbName).initializeDB()

    if not db.db.is_connected():
        raise Exception("Unable to access database")
        
    success, errorMessage, userDataFormat = completeJwtUserValidation(request)
        
    if not success:
        return responseJwtFormat(success, errorMessage, None)
    
    try:
        dataSet = db.getAllFacultyDetails()
        
        dataDictionary = {}
        
        count = 0
        
        for data in dataSet:
            dataDictionary[count] = shortFormatAllFacultyDetails(data)
            count += 1
        
    except:
        success = False
        errorMessage = "Error in user details"
        return responseJwtFormat(success, errorMessage, createJwtToken(userDataFormat))
    
    parse = responseJwtFormat(success, errorMessage, createJwtToken(userDataFormat))
    parse["data"] = dataDictionary
    
    return parse

@app.route('/faculty/update', methods=['PUT'])
@cross_origin()
def updateCurrentUser():
    db = DbManager(dbHost, dbPort, dbUser, dbPassword, dbName).initializeDB()
    
    success, errorMessage, userDataFormat = completeJwtUserValidation(request)
        
    if not success:
        return responseJwtFormat(success, errorMessage, None)
    
    try:
        try:
            userName = userDataFormat["userData"]["userName"]
            email = userDataFormat["userData"]["email"]
            name = request.values["firstName"] + " " + request.values["lastName"]
            designation = request.values["designation"]
            department = request.values["department"]
            address = request.values["address"] if request.values["address"] is not None else ''
            image = request.values["image"] if request.values["image"] is not None else ''
            imageExtension = request.values["imageExtension"] if request.values["imageExtension"] is not None else 'png'
            contacts = request.values["contacts"].split(";")
            contactDict = {}
            count = 0
            for data in contacts:
                contactDict[str(count)] = data
                count += 1
            print(contactDict)
        except Exception:
            success = False
            errorMessage = "Invalid form data"
            raise Exception(errorMessage)
            
        print(name)
        facultyDetails = userDetailsFormat(db.getFacultyDetails(userName, email), db.getFacultyContact(userName, email), False)
        print(facultyDetails)
        imageUrl = ''
        if (imageExtension != ''):
            try:
                imageUrl = imagePath + name.partition(" ")[0] + "_" + name.partition(" ")[3]  + "_" + getNoise() + "." + imageExtension
                print(imageUrl)
                image = image.replace(" ", "+")
                with open(imageUrl, 'wb') as file:
                    image = image.replace(" ", "+")
                    print(image)
                    file.write(codecs.decode(image.encode("utf-8"), "base64"))
                    
            except Exception as e:
                imageUrl = ''
                errorMessage = "No image was found"
                print(e)
                
        if imageUrl != '':
            os.remove(facultyDetails["image"])

        inPutCheck = userDetailsFormat(("", designation, name, address, department, imageUrl), contactDict, False)
                
        for data in facultyDetails:
            if inPutCheck[data] != '' or inPutCheck[data] != facultyDetails[data] and data != "contacts":
                facultyDetails[data] = inPutCheck[data]
                
        facultyDetails["contacts"] = inPutCheck["contacts"]
        
        nameArray = facultyDetails["name"].partition(" ")
        firstName = nameArray[0]
        lastName = nameArray[2]
        
        contacts = []
        for data in facultyDetails[contacts]:
            contacts.append(facultyDetails[contacts][data])
        
        
        try:
            db.removeFacultyContacts(userName, email).updateFacultyDetails(userName, email, firstName, lastName, facultyDetails["designation"], facultyDetails["department"], facultyDetails["address"], facultyDetails["image"], contacts)
            print(facultyDetails)
        except Exception:
            success = False
            errorMessage = "Data mismatch please check your input fields"
            return responseJwtFormat(success, errorMessage, None)
        
        db.commit()
        
    except Exception as e:
        print(e)
        return responseJwtFormat(success, errorMessage, createJwtToken(userDataFormat))
    
    return responseJwtFormat(success, errorMessage, createJwtToken(userDataFormat))
    
    

#%%


if __name__ == "__main__":
    app.run(host="192.168.0.102", port="3200")
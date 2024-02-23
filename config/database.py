from pymongo import MongoClient
import certifi

ca = certifi.where()

client = MongoClient("mongodb+srv://63010656:JumkR7Gtj1bTuRqh@data.7pzwf1b.mongodb.net/?retryWrites=true&w=majority", tlsCAFile=ca)

db = client.Roof_Surface_Website

collection_user = db["User"]
collection_factory = db["Factory"]
collection_building = db["Building"]
collection_Image = db["Image"]
collection_DefectLocation = db["DefectLocation"]
collection_Defect = db["Defect"]
collection_Permission = db["Permission"]
collection_history = db["History"]
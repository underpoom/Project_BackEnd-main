from pydantic import BaseModel,Field

class User(BaseModel):
    username : str = Field(max_length=20)
    password : str 
    is_admin : bool = False
    is_verified : bool = False
    user_verification_file_path : str

class Factory(BaseModel):
    factory_name : str
    factory_details : str

class Building(BaseModel):
    building_name : str
    building_detail : str
    building_length : float
    building_width : float
    data_location : str
    defect_sum : int
    each_defect_type_sum : str
    factory_name : str
    factory_details : str

class Image(BaseModel):
    image_path :str
    stitched_location_x : float
    stitched_location_y : float
    building_path : str

class DefectLocation(BaseModel):
    class_type : int
    x : float
    y : float
    w : float
    h : float

class Defect(BaseModel):
    defect_class : int
    defect_class_name : str

class Permission(BaseModel):
    have_permis : bool
    username : str
    factory_name : str
    factory_details : str


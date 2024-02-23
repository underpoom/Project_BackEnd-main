import requests

url = "http://localhost:8000/sign_up"

data = {
    "username": "user12",
    "password": "user12@123"
}

files = {'uploadedfile': open('Pasin_Keawnil_Transcript.pdf', 'rb')}  # Make sure to replace 'your_pdf_file.pdf' with the actual file path

response = requests.post(url, data=data, files=files)

print(response)
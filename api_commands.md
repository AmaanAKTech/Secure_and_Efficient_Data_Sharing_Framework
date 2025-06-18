
curl -X POST -H "Content-Type: application/json" \
     -d '{"username": "user1", "password": "password123"}' \
     http://localhost:5000/api/register


curl -X POST -H "Content-Type: application/json" -c cookies.txt \
     -d '{"username": "user1", "password": "password123"}' \
     http://localhost:5000/api/login


curl -X POST -b cookies.txt -F "file=@/path/to/your/file.txt" \
     http://localhost:5000/api/upload


curl -X GET -b cookies.txt http://localhost:5000/api/files


curl -X GET -b cookies.txt -o downloaded_file.txt \
     http://localhost:5000/api/file/<file_id>/download


curl -X DELETE -b cookies.txt \
     http://localhost:5000/api/file/<file_id>


curl -X POST -b cookies.txt http://localhost:5000/api/logout

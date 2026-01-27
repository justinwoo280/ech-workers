@echo off
set HTTP_PROXY=http://127.0.0.1:30000
set HTTPS_PROXY=http://127.0.0.1:30000
cd cmd\ech-workers
go build -v .

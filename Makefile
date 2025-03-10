por_lib:
	cmake -B ./build
	cmake --build ./build
	cp ./build/src/libpor.a ./app

por_lib_test:
	cmake --build ./build --target test

por_service: por_lib
	cd ./app && go build -o por_web_api

launch_web_api: por_service
	cd ./app && ./por_web_api -p eight_users.txt

docker:
	docker build -t test .
	docker run  -p 8080:8080 test
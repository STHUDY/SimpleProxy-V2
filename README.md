### SimpleProxy-V2
support tls and socket

### build

Debug
```
mkdir build
cd build
cmake ..
cmake --build . -j 1
```

Release
```
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . -j 1
```
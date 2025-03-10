# Run the test code
```
sudo make docker
Type in browser: http://127.0.0.1:8080/por?id=5
```

# Modules
## PoR Library
1. sha256 algorithm
2. tagged hash
3. merkle root calculation
4. PoR DB
   
   preprocess user data file to create index and persisted merkle tree.

   use mmap & mlock to accelerate query
       

## PoR Service
1. provide /por?id= to query user info and give it a merkle proot.
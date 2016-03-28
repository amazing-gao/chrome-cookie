# Openssl in mac
```sh
brew link openssl --force
```

# 使用方法
```sh
decryptor cookie文件路径 chrome钥匙串 [cookie的host] [cookie的名字]
```

# Mac下获取chrome钥匙串
```sh
security find-generic-password -w -s "Chrome Safe Storage"
```

# 编译
```sh
./build.sh
```

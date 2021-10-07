# xitapiga CTF赛题设计说明
### [题目信息]：
出题人|出题时间|题目名字|题目类型|难度等级|题目分值
:-|:-|:-|:-|:-|:-
1phan|20190414|xitapiga|crypto|5|600

### [题目描述]：
```
Are you a hacker or script kiddie？
```

### [题目考点]：
```
1. Golang 无符号表逆向
2. 哈希扩展攻击
3. 对双线性对的基础理解。或者其实不理解也能解题。
```

### [Flag ]:
`flag{2A1275319007988507038623161EFB134CFF121AAC10799BBCB039537AD7864C}`

### [题目环境]：
```
1. ubuntu 18.04 LTS（更新到最新）
2. github.com/Nik-U/pbc
```

### [题目制作过程]：
1. go build -ldflags "-s -w" main.go
2. ./main

### [题目writeup]：

题目本质是一个哈希扩展攻击。

见writeup文件夹。

### 注意事项
None
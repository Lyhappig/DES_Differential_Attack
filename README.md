## 结构

`./main.cpp` 测试文件

`./DES/des.cpp ./DES/des.hpp` DES算法文件

`./Three_Rounds` DES 3轮攻击代码

`./Six_Rounds` DES 6轮攻击代码

`./Eight_Rounds` DES 8轮攻击代码

## 编译

```bash
cd build
cmake ..
make
```

## 攻击方法

详见 `./doc/tutorial.md`

## 参考文献

Biham-Shamir1991_Article_DifferentialCryptanalysisOfDES
# remotecc
不落地方案是一个demo例子   
1、需要借助ssh的22端口进行进程自动落地、执行与擦除.   
2、需要事先获取局域网或远程主机的用户名与密码.       
gcc remotecc.c remotecc_test.c -L./lib -lssh2 -I./include -o LpDataRemoteTool

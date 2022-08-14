# Redis死循环异常

issue地址：[redis 99% cpu when master down · Issue #518 · redis/redis (github.com)](https://github.com/redis/redis/issues/518)

测试Redis版本：2.4.11

### 复现步骤

1台电脑，2个redis节点；

使用redis-master.conf启动master节点，redis-slave.conf启动slave节点；

此时slave节点会因为没有设置masterauth导致持续尝试与master建立主从关系，调用syncWrite；

启动后运行epoll_return.py注入异常，即可看到slave节点出现卡住，CPU占用飙升，日志提示 `I/O error writing to MASTER: Connection timed out`

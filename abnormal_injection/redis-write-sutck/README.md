# Redis write系统调用阻塞异常

异常报告地址：[Redis ，又抖了！ - 腾讯云开发者社区-腾讯云 (tencent.com)](https://cloud.tencent.com/developer/article/1872329)

### 复现步骤

1台机器，2个redis节点

使用redis-master.conf启动master节点，redis-slave.conf启动slave节点，至此2个节点运行正常；

运行busy_disk.py增加磁盘繁忙程度；

打开redis-cli，向slave节点设置部分key-value对，如 `set 100 100 set 50 50`，此时可以观察到某次设置时很长时间没有反应，slave节点的log提示 `Asynchronous **AOF** fsync is taking too **long**(disk is busy**?**)**.** Writing the **AOF** buffer without waiting **for** fsync to complete**,**this may slow down Redis**.**`

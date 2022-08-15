# Redis内存泄漏异常

异常报告：[[redis] github-417 (Release) (google.com)](https://docs.google.com/document/d/1lG_xPiaWwpEHcz558Kort7KGV8-3QYctNTNwluaqtLw/pub)

### 复现步骤

使用本目录下2个配置文件启动redis主从节点，执行inject.sh，待脚本执行完成即可观察到内存泄露的现象。

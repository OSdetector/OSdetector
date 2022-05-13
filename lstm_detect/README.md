# LSTM Anomaly Detection

## 设计

目录结构

```
dataset.py      # 数据处理部分，依赖numpy
                将输入数据变为(1, TIME_STEPS, DIMS)的shape
detect_onnx.py  # 模型的运行，依赖onnx和numpy

train.py        # 训练部分，依赖PyTorch
dataset_torch.py 
```

异常检测的原理是使用LSTM对`TIME_STEPS`长度的时间序列作为输入，预测下一个记录点的数据，如果超过阈值，那么认为存在异常

## Result

Data range: 21:49 - 23:58

Manually triggered high CPU usage at 22:14

```
2022-04-26 22:14:52 abnomal CPU usage
2022-04-26 22:33:15 abnomal CPU usage
2022-04-26 22:33:51 abnomal CPU usage
2022-04-26 22:52:54 abnomal CPU usage
2022-04-26 23:16:19 abnomal CPU usage
2022-04-26 23:20:09 abnomal CPU usage
2022-04-26 23:23:34 abnomal CPU usage
2022-04-26 23:36:27 abnomal CPU usage
2022-04-26 23:44:10 abnomal CPU usage
```
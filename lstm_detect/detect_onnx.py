import onnxruntime as ort
import numpy as np
from datetime import datetime
from dataset import DetectDataSet


if __name__ == '__main__':
    ort_sess = ort.InferenceSession("model.onnx")

    dataset = DetectDataSet("network.csv")

    for idx in range(len(dataset)):
        input, label, timestamp = dataset[idx]
        input = np.expand_dims(input, axis=1)
        input = np.expand_dims(input, axis=0)
        # label = np.expand_dims(label, axis=1)
        # label = np.expand_dims(label, axis=0)
        outputs = ort_sess.run(None, {'input': input})
        loss = np.sum(np.abs(outputs[0] - label))
        if (loss > 100):
            time = datetime.fromtimestamp(int(float(timestamp)))
            print(f"{time} abnomal CPU usage, {loss}")

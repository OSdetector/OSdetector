import csv
import numpy as np

TIME_STEPS = 80


def create_sequences(X, time_steps=TIME_STEPS):
    Xs, ys = [], []
    for i in range(len(X)-time_steps):
        Xs.append(X[i:(i+time_steps)])
        ys.append(X[i+time_steps])

    return np.array(Xs, dtype=np.float32), np.array(ys, dtype=np.float32)


class DetectDataSet(object):
    def __init__(self, data_path):
        self.data_path = data_path
        with open(data_path) as f:
            csv_reader = csv.reader(f)
            timestamp = []
            value = []
            for id, row in enumerate(csv_reader):
                if id == 0:
                    continue
                timestamp.append(row[0])
                value.append(row[3])
        self.data = {'timestamp': timestamp, 'value': value}
        tmp_data = create_sequences(self.data['value'])
        input, label = tmp_data
        self.data = {'input': input, 'label': label,
                     'timestamp': timestamp[79:-1]}
        self.length = len(self.data['input'])

    def __getitem__(self, index):
        return self.data['input'][index], self.data['label'][index], self.data['timestamp'][index]

    def __len__(self):
        return self.length

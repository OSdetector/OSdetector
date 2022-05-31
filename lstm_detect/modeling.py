import torch
from torch import nn


class Model(nn.Module):
    def __init__(self, input_size, hidden_size, num_layers, num_classes, device='cpu'):
        super(Model, self).__init__()
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        self.lstm = nn.LSTM(input_size, hidden_size,
                            num_layers, batch_first=True).to(device)
        self.fc = nn.Sequential(
            nn.Dropout(0.2),
            nn.Linear(hidden_size, num_classes).to(device)
        )
        self.device = device

    def forward(self, x):
        h0 = torch.zeros(self.num_layers, x.size(
            0), self.hidden_size).to(self.device)
        c0 = torch.zeros(self.num_layers, x.size(
            0), self.hidden_size).to(self.device)

        # forward propagate lstm
        out, (h_n, h_c) = self.lstm(x, (h0, c0))

        # 选取最后一个时刻的输出
        out = self.fc(out[:, -1, :])
        return out

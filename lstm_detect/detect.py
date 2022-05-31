import torch
from torch.utils.data import DataLoader

from modeling import Model
from dataset_torch import DetectDataSet
from datetime import datetime


device = 'cuda' if torch.cuda.is_available() else 'cpu'

if __name__ == '__main__':
    model = Model(1, 256, num_layers=2, num_classes=1, device=device)
    model.load_state_dict(torch.load("model.pkl"))
    model.to(device)
    model.eval()

    dataset = DetectDataSet("cpu.csv")
    dataloader = DataLoader(dataset,
                            batch_size=1,
                            shuffle=False)

    loss_func = torch.nn.L1Loss()

    export_flag = True

    for batch in dataloader:
        input, label, timestamp = batch
        input = input.to(device)
        label = label.to(device)
        if export_flag:
            torch.onnx.export(model, input, "model.onnx", input_names=[
                              "input"], output_names=["output"])
            export_flag = False
        output = model(input)
        loss = loss_func(output, label)

        if loss.item() > 60:
            time = datetime.fromtimestamp(int(float(timestamp[0])))
            print(f"{time} abnomal CPU usage, {loss}")

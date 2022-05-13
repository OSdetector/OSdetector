from sched import scheduler
import toml
import torch
from torch.utils.data import DataLoader
from torch.optim.lr_scheduler import ExponentialLR

from modeling import Model
from dataset_torch import DataSet

TIME_STEPS = 80
BATCH_SIZE = 64
NUM_EPOCHS = 20

device = 'cuda' if torch.cuda.is_available() else 'cpu'

if __name__ == "__main__":
    with open('input_data.toml') as f:  # load data path
        config = toml.loads(f.read())

    normal_data_path = config['normal']['data']

    train_data = DataSet(normal_data_path[0])
    train_dataloader = DataLoader(
        train_data,
        batch_size=BATCH_SIZE,
        shuffle=True)

    print("Data initialization done.")

    model = Model(1, 256, num_layers=2, num_classes=1, device=device)

    loss_func = torch.nn.L1Loss()
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-4)
    scheduler = ExponentialLR(optimizer, gamma=0.96)

    # Training loop
    for epoch_id in range(NUM_EPOCHS):
        cur_batch_loss = 0
        data_length = len(train_dataloader)
        for batch in train_dataloader:
            input, label = batch
            input = input.to(device)
            label = label.to(device)
            output = model(input)
            loss = loss_func(output, label)
            cur_batch_loss += loss.item()
            loss.backward()
            optimizer.step()

        scheduler.step()
        cur_batch_loss /= data_length
        print(
            f"Epoch {epoch_id+1} Avg Loss: {cur_batch_loss}, cur_lr: {scheduler.get_last_lr()}")

    torch.save(model.state_dict(), "model.pkl")

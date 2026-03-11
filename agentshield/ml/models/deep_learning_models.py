"""Deep learning based anomaly detection using PyTorch"""

from typing import Any, Dict, List, Optional
import numpy as np

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import DataLoader, TensorDataset
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False


class AutoencoderAnomalyDetector(nn.Module):
    """Autoencoder for anomaly detection"""

    def __init__(self, input_dim: int, hidden_dims: List[int] = [64, 32, 16]):
        super().__init__()

        self.encoder = nn.ModuleList()
        self.decoder = nn.ModuleList()

        dims = [input_dim] + hidden_dims
        for i in range(len(dims) - 1):
            self.encoder.append(nn.Linear(dims[i], dims[i + 1]))
            self.decoder.insert(0, nn.Linear(dims[i + 1], dims[i]))

        self.relu = nn.ReLU()
        self.sigmoid = nn.Sigmoid()

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        for layer in self.encoder:
            x = self.relu(layer(x))

        for layer in self.decoder:
            x = self.sigmoid(layer(x))

        return x


class PyTorchAnomalyDetector:
    """PyTorch-based deep learning anomaly detector"""

    def __init__(
        self,
        input_dim: int,
        hidden_dims: List[int] = [64, 32, 16],
        learning_rate: float = 0.001,
        epochs: int = 100,
        batch_size: int = 32,
        threshold: float = 0.1
    ):
        self.input_dim = input_dim
        self.hidden_dims = hidden_dims
        self.learning_rate = learning_rate
        self.epochs = epochs
        self.batch_size = batch_size
        self.threshold = threshold

        self._model = None
        self._optimizer = None
        self._criterion = None
        self._is_trained = False
        self._device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    @property
    def is_available(self) -> bool:
        return TORCH_AVAILABLE

    def train(
        self,
        X: List[List[float]],
        validation_split: float = 0.2
    ) -> Dict[str, Any]:
        """Train the autoencoder model"""
        if not TORCH_AVAILABLE:
            return {
                "success": False,
                "error": "PyTorch not installed. Install with: pip install torch"
            }

        try:
            X_array = np.array(X, dtype=np.float32)
            if len(X_array.shape) == 1:
                X_array = X_array.reshape(-1, 1)

            self._model = AutoencoderAnomalyDetector(
                input_dim=X_array.shape[1],
                hidden_dims=self.hidden_dims
            ).to(self._device)

            self._optimizer = optim.Adam(self._model.parameters(), lr=self.learning_rate)
            self._criterion = nn.MSELoss()

            dataset = TensorDataset(torch.tensor(X_array))
            train_size = int(len(dataset) * (1 - validation_split))
            val_size = len(dataset) - train_size

            train_dataset, val_dataset = torch.utils.data.random_split(
                dataset, [train_size, val_size]
            )

            train_loader = DataLoader(train_dataset, batch_size=self.batch_size, shuffle=True)
            val_loader = DataLoader(val_dataset, batch_size=self.batch_size)

            best_loss = float("inf")

            for epoch in range(self.epochs):
                self._model.train()
                train_loss = 0.0

                for batch in train_loader:
                    data = batch[0].to(self._device)

                    self._optimizer.zero_grad()
                    output = self._model(data)
                    loss = self._criterion(output, data)

                    loss.backward()
                    self._optimizer.step()

                    train_loss += loss.item()

                train_loss /= len(train_loader)

                self._model.eval()
                val_loss = 0.0

                with torch.no_grad():
                    for batch in val_loader:
                        data = batch[0].to(self._device)
                        output = self._model(data)
                        loss = self._criterion(output, data)
                        val_loss += loss.item()

                val_loss /= len(val_loader)

                if val_loss < best_loss:
                    best_loss = val_loss

            self._is_trained = True

            return {
                "success": True,
                "message": "Model trained successfully",
                "best_loss": float(best_loss),
                "device": str(self._device)
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def predict(self, X: List[List[float]]) -> List[int]:
        """Predict anomalies (1 for normal, -1 for anomaly)"""
        if not self._is_trained:
            raise ValueError("Model not trained yet")

        X_array = np.array(X, dtype=np.float32)
        if len(X_array.shape) == 1:
            X_array = X_array.reshape(-1, 1)

        self._model.eval()
        predictions = []

        with torch.no_grad():
            for i in range(0, len(X_array), self.batch_size):
                batch = torch.tensor(X_array[i:i + self.batch_size]).to(self._device)
                output = self._model(batch)
                loss = torch.mean((output - batch) ** 2, dim=1)

                for l in loss:
                    predictions.append(1 if l.item() < self.threshold else -1)

        return predictions

    def predict_scores(self, X: List[List[float]]) -> List[float]:
        """Predict anomaly scores (lower is more anomalous)"""
        if not self._is_trained:
            raise ValueError("Model not trained yet")

        X_array = np.array(X, dtype=np.float32)
        if len(X_array.shape) == 1:
            X_array = X_array.reshape(-1, 1)

        self._model.eval()
        scores = []

        with torch.no_grad():
            for i in range(0, len(X_array), self.batch_size):
                batch = torch.tensor(X_array[i:i + self.batch_size]).to(self._device)
                output = self._model(batch)
                loss = torch.mean((output - batch) ** 2, dim=1)

                for l in loss:
                    scores.append(float(l.item()))

        return scores

    def save_model(self, path: str) -> bool:
        """Save model to disk"""
        try:
            torch.save({
                "model_state_dict": self._model.state_dict(),
                "optimizer_state_dict": self._optimizer.state_dict(),
                "input_dim": self.input_dim,
                "hidden_dims": self.hidden_dims,
                "threshold": self.threshold
            }, path)
            return True
        except Exception:
            return False

    def load_model(self, path: str) -> bool:
        """Load model from disk"""
        try:
            checkpoint = torch.load(path, map_location=self._device)

            self.input_dim = checkpoint["input_dim"]
            self.hidden_dims = checkpoint["hidden_dims"]
            self.threshold = checkpoint["threshold"]

            self._model = AutoencoderAnomalyDetector(
                input_dim=self.input_dim,
                hidden_dims=self.hidden_dims
            ).to(self._device)
            self._model.load_state_dict(checkpoint["model_state_dict"])

            self._optimizer = optim.Adam(self._model.parameters())
            self._optimizer.load_state_dict(checkpoint["optimizer_state_dict"])

            self._criterion = nn.MSELoss()
            self._is_trained = True

            return True
        except Exception:
            return False


class LSTMSequenceClassifier(nn.Module):
    """LSTM for sequence classification"""

    def __init__(
        self,
        input_size: int,
        hidden_size: int = 64,
        num_layers: int = 2,
        num_classes: int = 2
    ):
        super().__init__()

        self.lstm = nn.LSTM(
            input_size=input_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=0.2
        )

        self.fc = nn.Linear(hidden_size, num_classes)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        lstm_out, _ = self.lstm(x)
        last_output = lstm_out[:, -1, :]
        output = self.fc(last_output)
        return self.sigmoid(output)


class SequenceAnomalyClassifier:
    """Sequence-based anomaly classifier using LSTM"""

    def __init__(
        self,
        input_size: int,
        hidden_size: int = 64,
        num_layers: int = 2,
        learning_rate: float = 0.001,
        epochs: int = 50,
        batch_size: int = 32
    ):
        self.input_size = input_size
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        self.learning_rate = learning_rate
        self.epochs = epochs
        self.batch_size = batch_size

        self._model = None
        self._optimizer = None
        self._criterion = nn.BCELoss()
        self._is_trained = False
        self._device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    @property
    def is_available(self) -> bool:
        return TORCH_AVAILABLE

    def train(
        self,
        sequences: List[List[List[float]]],
        labels: List[int]
    ) -> Dict[str, Any]:
        """Train sequence classifier"""
        if not TORCH_AVAILABLE:
            return {
                "success": False,
                "error": "PyTorch not installed"
            }

        try:
            X_array = np.array(sequences, dtype=np.float32)
            y_array = np.array(labels, dtype=np.float32).reshape(-1, 1)

            if len(X_array.shape) == 2:
                X_array = X_array.reshape(X_array.shape[0], X_array.shape[1], 1)

            dataset = TensorDataset(
                torch.tensor(X_array),
                torch.tensor(y_array)
            )

            dataloader = DataLoader(dataset, batch_size=self.batch_size, shuffle=True)

            self._model = LSTMSequenceClassifier(
                input_size=self.input_size,
                hidden_size=self.hidden_size,
                num_layers=self.num_layers,
                num_classes=1
            ).to(self._device)

            self._optimizer = optim.Adam(self._model.parameters(), lr=self.learning_rate)

            for epoch in range(self.epochs):
                self._model.train()
                total_loss = 0.0

                for batch_x, batch_y in dataloader:
                    batch_x = batch_x.to(self._device)
                    batch_y = batch_y.to(self._device)

                    self._optimizer.zero_grad()
                    outputs = self._model(batch_x)
                    loss = self._criterion(outputs, batch_y)

                    loss.backward()
                    self._optimizer.step()

                    total_loss += loss.item()

            self._is_trained = True

            return {
                "success": True,
                "message": "Sequence classifier trained",
                "avg_loss": total_loss / len(dataloader),
                "device": str(self._device)
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def predict(self, sequences: List[List[List[float]]]) -> List[int]:
        """Predict sequence labels"""
        if not self._is_trained:
            raise ValueError("Model not trained yet")

        X_array = np.array(sequences, dtype=np.float32)

        if len(X_array.shape) == 2:
            X_array = X_array.reshape(X_array.shape[0], X_array.shape[1], 1)

        self._model.eval()
        predictions = []

        with torch.no_grad():
            batch = torch.tensor(X_array).to(self._device)
            outputs = self._model(batch)

            for output in outputs:
                predictions.append(1 if output.item() > 0.5 else 0)

        return predictions

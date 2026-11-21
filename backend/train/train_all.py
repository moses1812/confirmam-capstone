"""Rebuild both AI models:  python -m train.train_all
Run this after adding data/extra_messages.csv or if the app says it could not load a model."""
from . import make_ng_messages, train_message_model, train_url_model

if __name__ == "__main__":
    make_ng_messages.main()
    train_message_model.main()
    train_url_model.main()

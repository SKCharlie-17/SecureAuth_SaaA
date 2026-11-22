
from secureauth.core import FaceEngine

IMAGE_PATH = r"test.jpeg"


def main():
    engine = FaceEngine()

    print("Testing face extraction...")

    embedding = engine.extract_face_embedding(IMAGE_PATH)

    print("Face detected successfully!")
    print("Embedding dimensions:", len(embedding))
    print("Embedding generated:", len(embedding) > 0)


if __name__ == "__main__":
    main()

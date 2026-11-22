
import cv2
import numpy as np

from pathlib import Path


class FaceEngine:

    def __init__(
        self,
        detector_model=None,
        recognizer_model=None
    ):

        # Default model directory inside SecureAuth package
        MODEL_DIR = Path(__file__).resolve().parent.parent / "models"

        self.detector_model = (
            Path(detector_model)
            if detector_model
            else MODEL_DIR / "face_detection_yunet_2023mar.onnx"
        )

        self.recognizer_model = (
            Path(recognizer_model)
            if recognizer_model
            else MODEL_DIR / "face_recognition_sface_2021dec.onnx"
        )

        # Check whether model files exist
        if not self.detector_model.exists():
            raise FileNotFoundError(
                f"YuNet model not found: {self.detector_model}"
            )

        if not self.recognizer_model.exists():
            raise FileNotFoundError(
                f"SFace model not found: {self.recognizer_model}"
            )

        # Load YuNet detector
        self.face_detector = cv2.FaceDetectorYN.create(
            str(self.detector_model),
            "",
            (640, 480),
            0.7,
            0.3,
            5000
        )

        # Load SFace recognizer
        self.face_recognizer = cv2.FaceRecognizerSF.create(
            str(self.recognizer_model),
            ""
        )

    def extract_face_embedding(self, image_path):

        # Read photograph
        image = cv2.imread(str(image_path))

        if image is None:
            raise ValueError("Could not read the uploaded image")

        # Resize image for detection
        resized_image = cv2.resize(image, (640, 480))

        self.face_detector.setInputSize((640, 480))

        # Detect face
        _, faces = self.face_detector.detect(resized_image)

        if faces is None or len(faces) == 0:
            raise ValueError(
                "No face detected. Please try again."
            )

        if len(faces) > 1:
            raise ValueError(
                "Multiple faces detected. Only one person is allowed."
            )

        # Align face
        aligned_face = self.face_recognizer.alignCrop(
            resized_image,
            faces[0]
        )

        # Extract numerical features
        embedding = self.face_recognizer.feature(aligned_face)

        # Return Python list
        return embedding.flatten().astype(float).tolist()

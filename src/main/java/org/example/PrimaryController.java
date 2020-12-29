package org.example;

import javafx.scene.control.*;
import javafx.scene.image.Image;
import javafx.scene.layout.Pane;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Scanner;

public class PrimaryController {
    public Pane background;
    public Button genButton;
    public TextArea plaintextArea;
    public TextArea signatureArea;
    public Button signButton;
    private final RSA rsa = new RSA();
    public TextField publicKeyText;
    public TextField privateKeyText;
    public TextField moduloText;
    public TextField blindingFactorText;
    public TextField inputPathText;
    public Button inputFileButton;
    public Button outputFileButton;
    public TextField outputPathText;

    public void generate() {
        rsa.generateKey();
        publicKeyText.setText(rsa.e.toString(16).toUpperCase());
        privateKeyText.setText(rsa.d.toString(16).toUpperCase());
        moduloText.setText(rsa.N.toString(16).toUpperCase());
        blindingFactorText.setText(rsa.k.toString(16).toUpperCase());
    }

    private void popupError(String message) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("Chaeyoung says:");
        Stage stage = (Stage) alert.getDialogPane().getScene().getWindow();
        stage.getIcons().add(new Image(getClass().getResource("faworytkaicon.png").toExternalForm()));
        alert.setHeaderText(null);
        alert.setResizable(false);
        alert.setContentText(message);
        alert.showAndWait();
    }

    private void loadFromFields() {
        try {
            rsa.e = new BigInteger(publicKeyText.getText(), 16);
            rsa.d = new BigInteger(privateKeyText.getText(), 16);
            rsa.N = new BigInteger(moduloText.getText(), 16);
            rsa.k = new BigInteger(blindingFactorText.getText(), 16);
        } catch (NumberFormatException e) {
            popupError("At least one key related input is invalid. \nPlease use hexadecimal.");
        }

    }

    public void signPlaintextArea() {
        loadFromFields();
        signatureArea.setText(rsa.podpisujSlepo(plaintextArea.getText()).toString(16).toUpperCase());
    }

    public void verifyFromStrings(String text, String signature) {
        if (rsa.weryfikujStringSlepo(text, signature)) {
            Alert alert = new Alert(Alert.AlertType.NONE, "Verification succesful!", ButtonType.OK);
            Stage stage = (Stage) alert.getDialogPane().getScene().getWindow();
            alert.setTitle("Success");
            alert.setResizable(false);
            stage.getIcons().add(new Image(getClass().getResource("iconsuccess.png").toExternalForm()));
            alert.showAndWait();
        } else {
            Alert alert = new Alert(Alert.AlertType.NONE, "Verification unsuccesful!", ButtonType.OK);
            Stage stage = (Stage) alert.getDialogPane().getScene().getWindow();
            alert.setTitle("Failure");
            alert.setResizable(false);
            stage.getIcons().add(new Image(getClass().getResource("iconfail.png").toExternalForm()));
            alert.showAndWait();
        }
    }

    public void verifyTextAreas() {
        loadFromFields();
        if (rsa.weryfikujStringSlepo(plaintextArea.getText(), signatureArea.getText())) {
            Alert alert = new Alert(Alert.AlertType.NONE, "Verification succesful!", ButtonType.OK);
            Stage stage = (Stage) alert.getDialogPane().getScene().getWindow();
            alert.setTitle("Success");
            alert.setResizable(false);
            stage.getIcons().add(new Image(getClass().getResource("iconsuccess.png").toExternalForm()));
            alert.showAndWait();
        } else {
            Alert alert = new Alert(Alert.AlertType.NONE, "Verification unsuccesful!", ButtonType.OK);
            Stage stage = (Stage) alert.getDialogPane().getScene().getWindow();
            alert.setTitle("Failure");
            alert.setResizable(false);
            stage.getIcons().add(new Image(getClass().getResource("iconfail.png").toExternalForm()));
            alert.showAndWait();
        }
    }

    private void chooseFile(TextField pathText) {
        Stage stage = new Stage();
        FileChooser fileChooser = new FileChooser();
        try {
            pathText.setText(fileChooser.showOpenDialog(stage).getAbsolutePath());
            fileChooser.setTitle("Choose a file:");
        } catch (RuntimeException e) {
            pathText.setText("");
        }
    }

    public void chooseInputFile() {
        chooseFile(inputPathText);
    }

    public void chooseOutputFile() {
        chooseFile(outputPathText);
    }

    public void signFile() {
        loadFromFields();
        try {
            FileWriter fileWriter = new FileWriter(outputPathText.getText());
            fileWriter.write(rsa.podpisujSlepo(Files.readAllBytes(Paths.get(inputPathText.getText()))).toString(16).toUpperCase());
            fileWriter.close();
        } catch (IOException e) {
            popupError("No or invalid file chosen.");
        }
    }

    public void verifyFiles() {
        loadFromFields();
        try {
            String input = new String(Files.readAllBytes(Paths.get(inputPathText.getText()))).trim();
            String signature = new String(Files.readAllBytes(Paths.get(outputPathText.getText()))).trim();
            verifyFromStrings(input, signature);
        } catch (IOException e) {
            popupError("No or invalid file chosen.");
        }
    }



}

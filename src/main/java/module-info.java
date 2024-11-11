module com.example.encryptdecript {
    requires javafx.controls;
    requires javafx.fxml;


    opens com.example.encryptdecript to javafx.fxml;
    exports com.example.encryptdecript;
}
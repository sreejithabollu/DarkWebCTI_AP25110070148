package darkwebcti;

import java.awt.BorderLayout;
import java.awt.Button;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Frame;
import java.awt.Label;
import java.awt.Panel;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

import javax.swing.SwingUtilities;

public class AwtLauncher extends Frame {

    public AwtLauncher() {
        super("Dark Web CTI");
        setSize(new Dimension(520, 220));
        setLocationRelativeTo(null);
        setResizable(false);
        setLayout(new BorderLayout(12, 12));
        setBackground(new Color(245, 247, 250));

        Label title = new Label("Dark Web Cyber Threat Intelligence", Label.CENTER);
        title.setFont(new Font("SansSerif", Font.BOLD, 20));

        Label subtitle = new Label(
            "Launch the dataset analysis and threat intelligence interface",
            Label.CENTER
        );

        Panel center = new Panel(new BorderLayout(8, 8));
        center.add(title, BorderLayout.NORTH);
        center.add(subtitle, BorderLayout.CENTER);

        Button launchButton = new Button("Launch Analysis GUI");
        launchButton.setPreferredSize(new Dimension(220, 44));
        launchButton.setFont(new Font("SansSerif", Font.BOLD, 14));
        launchButton.addActionListener(event -> launchApplication());

        Panel footer = new Panel();
        footer.add(launchButton);

        add(center, BorderLayout.CENTER);
        add(footer, BorderLayout.SOUTH);

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent event) {
                dispose();
                System.exit(0);
            }
        });
    }

    private void launchApplication() {
        SwingUtilities.invokeLater(() -> {
            try {
                Main.main(new String[0]);
            } catch (Exception exception) {
                exception.printStackTrace();
            }
        });
        dispose();
    }

    public static void main(String[] args) {
        AwtLauncher launcher = new AwtLauncher();
        launcher.setVisible(true);
    }
}

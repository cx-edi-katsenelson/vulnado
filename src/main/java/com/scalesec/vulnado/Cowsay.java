package com.scalesec.vulnado;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;

public class Cowsay {
  public static String run(String input) {
    // Use ProcessBuilder with an explicit argument list (no shell invocation).
    // Passing the user-supplied string as a discrete argument to cowsay prevents
    // shell meta-character interpretation and eliminates the command-injection
    // vulnerability present when constructing a shell string with user input.
    ProcessBuilder processBuilder = new ProcessBuilder(
        Arrays.asList("/usr/games/cowsay", input));

    StringBuilder output = new StringBuilder();

    try {
      Process process = processBuilder.start();
      BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

      String line;
      while ((line = reader.readLine()) != null) {
        output.append(line).append("\n");
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
    return output.toString();
  }
}

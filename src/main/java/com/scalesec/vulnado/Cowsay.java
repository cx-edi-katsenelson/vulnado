package com.scalesec.vulnado;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class Cowsay {
  public static String run(String input) {
    // No shell is involved: the executable is hardcoded and the user input is passed as a
    // single literal argv element, so shell metacharacters have no special meaning.
    // "--" stops option parsing so input starting with "-" cannot be treated as a flag.
    ProcessBuilder processBuilder = new ProcessBuilder("/usr/games/cowsay", "--", input);

    StringBuilder output = new StringBuilder();

    try {
      Process process = processBuilder.start();
      BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

      String line;
      while ((line = reader.readLine()) != null) {
        output.append(line + "\n");
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
    return output.toString();
  }
}

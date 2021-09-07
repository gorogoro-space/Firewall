package space.gorogoro.firewall;

import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.logging.Level;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent.Result;
import org.bukkit.plugin.java.JavaPlugin;

public class Firewall extends JavaPlugin implements Listener{
  private Connection con;
  private FileConfiguration config;
  private ArrayList<ArrayList<Long>> blockNetsetIpv4List = new ArrayList<ArrayList<Long>>();
  private List<String> unblockUUIDList = new ArrayList<String>();

  @Override
  public boolean onCommand( CommandSender sender, Command commandInfo, String label, String[] args) {
    // Return true:Success false:Show the usage set in plugin.yml
    try{
      if(!commandInfo.getName().equals("firewall") || !sender.isOp()) {
        return true;
      }

      if(args.length < 1) {
        sendMsg(sender, "The parameters are not enough.");
        return true;
      }

      boolean ret = true;
      switch(args[0]) {
        case "add":
          if(args.length != 3) {
            sendMsg(sender, "Invalid parameter. (Number of parameters)");
            return true;
          }

          if(args[1].equals("uuid")) {
            ret = commandAddUUID(sender, commandInfo, label, args);
          } else {
            sendMsg(sender, "Invalid parameter. (Processing type)");
          }
          break;

        case "check":
          if(args.length != 3) {
            sendMsg(sender, "Invalid parameter. (Number of parameters)");
            return true;
          }

          if(args[1].equals("uuid")) {
            ret = commandCheckUUID(sender, commandInfo, label, args);
          } else if(args[1].equals("ipaddr")) {
            ret = commandCheckIpAddr(sender, commandInfo, label, args);
          } else {
            sendMsg(sender, "Invalid parameter. (Processing type)");
          }
          break;

        case "delete":
          if(args.length != 3) {
            sendMsg(sender, "Invalid parameter. (Number of parameters)");
            return true;
          }

          if(args[1].equals("uuid")) {
            ret = commandDeleteUUID(sender, commandInfo, label, args);
          } else {
            sendMsg(sender, "Invalid parameter. (Processing type)");
          }
          break;

        case "long":
          if(args.length != 3) {
            sendMsg(sender, "Invalid parameter. (Number of parameters)");
            return true;
          }

          if(args[1].equals("cidr")) {
            ret = commandLongCIDR(sender, commandInfo, label, args);
          } else {
            sendMsg(sender, "Invalid parameter. (Processing type)");
          }
          break;

       case "reload":
          if(args.length != 1) {
            sendMsg(sender, "Invalid parameter. (Number of parameters)");
            return true;
          }
          ret = commandReload(sender, commandInfo, label, args);
          break;

        default:
          break;
      }
      return ret;
    } catch (Exception e) {
      logStackTrace(e);
    }
    return true;
  }

  @Override
  public void onDisable(){
    try {
      con.close();
    } catch (SQLException e) {
      logStackTrace(e);
    }
    getLogger().info("The Plugin Has Been Disabled!");
  }

  @Override
  public void onEnable(){
    try{
      getLogger().info("The Plugin Has Been Enabled!");
      getServer().getPluginManager().registerEvents(this, this);

      File configFile = new File(getDataFolder() + File.separator + "config.yml");
      if(!configFile.exists()){
        saveDefaultConfig();
      }

      Class.forName("org.sqlite.JDBC");
      con = DriverManager.getConnection("jdbc:sqlite:" + getDataFolder() + File.separator + "block.db");
      con.setAutoCommit(false);
      Statement stmt = con.createStatement();
      stmt.setQueryTimeout(30);
      stmt.executeUpdate("CREATE TABLE IF NOT EXISTS block_list (id INTEGER PRIMARY KEY AUTOINCREMENT, cidr STRING NOT NULL, start LONG NOT NULL, end LONG NOT NULL);");
      stmt.executeUpdate("CREATE UNIQUE INDEX IF NOT EXISTS block_list_cidr_uindex ON block_list (cidr, start, end);");
      stmt.executeUpdate("CREATE INDEX IF NOT EXISTS block_list_start_end_index ON block_list (start, end);");
      stmt.close();

      config = getConfig();
      storeBlockNetsetList(con);
      loadBlockNetsetList();
      unblockUUIDList = config.getStringList("list-unblock-uuid");

    } catch (Exception e) {
      logStackTrace(e);
    }
  }

  @EventHandler
  public void onAsyncPlayerPreLoginEvent(AsyncPlayerPreLoginEvent event){
    try {
      Long addr = ipv4ToLong(event.getAddress().getHostAddress().toString());

      if(unblockUUIDList.contains(event.getUniqueId().toString()) == false) {
        for(ArrayList<Long> range:blockNetsetIpv4List) {
          if(range.get(0) <= addr && addr <= range.get(1)) {
            event.disallow(Result.KICK_OTHER, config.getString("message-kick"));
          }
        }
      }
    } catch (Exception e) {
      logStackTrace(e);
    }
  }

  private boolean isUUIDFormat(String str) {
    if(str.length() != 36) {
      return false;
    }

    Pattern pattern = Pattern.compile("^[0-9a-f]{8}\\-[0-9a-f]{4}\\-[0-9a-f]{4}\\-[0-9a-f]{4}\\-[0-9a-f]{12}$");
    Matcher matcher = pattern.matcher(str);
    return matcher.matches();
  }

  private boolean commandReload(CommandSender sender, Command commandInfo, String label, String[] args) {
    onDisable();
    onEnable();
    sendMsg(sender, "Reload complete.");
    return true;
  }

  private boolean commandAddUUID(CommandSender sender, Command commandInfo, String label, String[] args) {
    String uuid = args[2].toLowerCase();
    if(!isUUIDFormat(uuid)) {
      sendMsg(sender, "Invalid UUID format. The format of UUID should be specified by xxxxxxxxx-xxxx-xxxx-xxxx-xxxx-xxxxxxxx.");
      return true;
    }

    if(unblockUUIDList.contains(uuid)) {
      sendMsg(sender, uuid + " is already registered.");
      return true;
    }

    String path = "list-unblock-uuid";
    List<String> list = config.getStringList(path);
    if(list.contains(uuid)) {
      sendMsg(sender, uuid + " is already registered. Please execute command '/firewall reload'.");
      return true;
    }

    list.add(uuid);
    Collections.sort(list);
    config.set(path, list);
    saveConfig();
    sendMsg(sender, uuid + " has been saved.");
    return true;
  }

  private boolean commandCheckIpAddr(CommandSender sender, Command commandInfo, String label, String[] args) {
    if(!isIpv4(args[2])) {
      sendMsg(sender, "Invalid IP address format. (Ipv4)");
      return true;
    }

    Long addr = ipv4ToLong(args[2]);
    for(ArrayList<Long> range:blockNetsetIpv4List) {
      if(range.get(0) <= addr && addr <= range.get(1)) {
        sendMsg(sender, args[2] + " is blocked.");
        return true;
      }
    }
    sendMsg(sender, args[2] + " is not blocked.");
    return true;
  }

  private boolean commandDeleteUUID(CommandSender sender, Command commandInfo, String label, String[] args) {
    String uuid = args[2].toLowerCase();
    if(!isUUIDFormat(uuid)) {
      sendMsg(sender, "Invalid UUID format. The format of UUID should be specified by xxxxxxxxx-xxxx-xxxx-xxxx-xxxx-xxxxxxxx.");
      return true;
    }

    if(!unblockUUIDList.contains(uuid)) {
      sendMsg(sender, uuid + " is not registered.");
      return true;
    }

    String path = "list-unblock-uuid";
    List<String> list = config.getStringList(path);
    if(!list.contains(uuid)) {
      sendMsg(sender, uuid + " is not registered. Please execute command '/firewall reload'.");
      return true;
    }

    list.remove(list.indexOf(uuid));
    Collections.sort(list);
    config.set(path, list);
    saveConfig();
    sendMsg(sender, uuid + " has been deleted.");
    return true;
  }

  private boolean commandCheckUUID(CommandSender sender, Command commandInfo, String label, String[] args) {
    String uuid = args[2].toLowerCase();
    if(!isUUIDFormat(uuid)) {
      sendMsg(sender, "Invalid UUID format. The format of UUID should be specified by xxxxxxxxx-xxxx-xxxx-xxxx-xxxx-xxxxxxxx.");
      return true;
    }

    if(unblockUUIDList.contains(uuid)) {
      sendMsg(sender, uuid + " is unblocked.");
    } else {
      sendMsg(sender, uuid + " is not unblocked.");
    }
    return true;
  }

  private boolean commandLongCIDR(CommandSender sender, Command commandInfo, String label, String[] args) {
    if(!isIpv4CIDR(args[2])) {
      sendMsg(sender, "Invalid CIDR format. (Ipv4)");
      return true;
    }

    String[] range = cidrToIpv4(args[2]);
    sendMsg(sender, String.format("The Long value is 'start:%d end:%d'.", ipv4ToLong(range[0]), ipv4ToLong(range[1])));
    return true;
  }

  private void storeBlockNetsetList(Connection con) throws SQLException {
    try {
      File dest = new File(getDataFolder() + File.separator + "stored" + File.separator);
      if(!dest.exists()) {
        dest.mkdir();
      }
      int rows = 0;
      String[] range;
      List<String> lines;
      HashMap<String,PreparedStatement> prepStmt;
      File f;
      ResultSet rs;
      for(String fileName : config.getStringList("list-block-netset-file")){
        f = new File(getDataFolder() + File.separator + fileName);
        if(!f.exists()) {
          continue;
        }
        getLogger().info("Found. path=" + f.getPath());

        lines = Files.readAllLines(f.toPath());
        prepStmt = new HashMap<>();
        prepStmt.put("select",con.prepareStatement("SELECT 1 FROM block_list WHERE cidr = ?;"));
        prepStmt.put("insert",con.prepareStatement("INSERT INTO block_list(cidr, start, end) VALUES (?, ?, ?);"));
        rows = 0;
        for(String line: lines) {
          if(!isIpv4(line) && !isIpv4CIDR(line)) {
            continue;
          }

          prepStmt.get("select").setString(1, line);
          rs = prepStmt.get("select").executeQuery();
          if(rs.next()){
            rs.close();
            continue;
          }
          rs.close();

          prepStmt.get("insert").setString(1, line);
          range = cidrToIpv4(line);
          prepStmt.get("insert").setLong(2, ipv4ToLong(range[0]));
          prepStmt.get("insert").setLong(3, ipv4ToLong(range[1]));
          prepStmt.get("insert").addBatch();
          rows++;
        }
        prepStmt.get("insert").executeBatch();
        con.commit();
        for(PreparedStatement p:prepStmt.values()) {
          p.close();
        }

        Files.move(Paths.get(f.getPath()), Paths.get(dest.getPath() + File.separator + fileName));
        getLogger().info("Stored. rows=" + rows + " path=" + f.getPath());
      }
      con.commit();
    } catch (Exception e) {
      logStackTrace(e);
      con.rollback();
    }
  }

  private void loadBlockNetsetList() {
    try {
      blockNetsetIpv4List = new ArrayList<ArrayList<Long>>();
      HashMap<String,PreparedStatement> prepStmt = new HashMap<>();
      prepStmt.put("select",con.prepareStatement("SELECT start, end FROM block_list;"));
      ResultSet rs;
      rs = prepStmt.get("select").executeQuery();
      while(rs.next()){
        blockNetsetIpv4List.add(new ArrayList<Long>(Arrays.asList(rs.getLong(1), rs.getLong(2))));
      }
      rs.close();
    } catch (Exception e) {
      logStackTrace(e);
    }
  }

  private static boolean isIpv4(String str) {
    try {
      if(str.length() < 7 || str.length() > 15) {
        return false;
      }

      Pattern pattern = Pattern.compile("^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$");
      Matcher matcher = pattern.matcher(str);
      if(!matcher.matches()) {
        return false;
      }

      if (!(InetAddress.getByName(str) instanceof Inet4Address)) {
        return false;
      }
      return true;
    } catch (UnknownHostException e) {
      return false;
    }
  }

  private static boolean isIpv4CIDR(String str) {
    if(str.length() < 7 || str.length() > 18) {
      return false;
    }
    String[] arrIp = str.split("/");
    if (arrIp.length != 2) {
      return false;
    }
    if (!isIpv4(arrIp[0])) {
      return false;
    }
    int mask = Integer.parseInt(arrIp[1]);
    if (mask < 0 || mask > 32) {
      return false;
    }
    return true;
  }

  private static String[] cidrToIpv4(String str) {
    String[] arrIp = str.split("/");
    Long start = ipv4ToLong(arrIp[0]);
    int subNetMask = 32;
    if (arrIp.length == 2) {
      subNetMask = Integer.parseInt(arrIp[1]);
    }
    Long num = pow(2, 32 - subNetMask);
    Long end = start + num - 1;
    String[] ret = {arrIp[0], longToIpv4(end)};
    return ret;
  }

  private static long ipv4ToLong(String str) {
    String[] arrAddr = str.split("\\.");
    Long num = 0L;
    for (int i=0;i<arrAddr.length;i++) {
      int power = 3-i;
      num += ((Integer.parseInt(arrAddr[i]) % 256) * pow(256,power));
    }
    return num;
  }

  private static String longToIpv4(Long longIp){
    return String.format(
      "%d.%d.%d.%d",
      ((longIp >> 24) & 0xFF),
      ((longIp >> 16) & 0xFF),
      ((longIp >> 8) & 0xFF),
      (longIp & 0xFF)
    );
  }

  private static long pow(int number, int power) {
    if(power == 0) {
      return 1;
    }
    int result = number;
    while(power > 1) {
      result*=number;
      power--;
    }
    return (long)result;
  }

  private static void logStackTrace(Exception e){
    StringWriter sw = new StringWriter();
    PrintWriter pw = new PrintWriter(sw);
    e.printStackTrace(pw);
    pw.flush();
    Bukkit.getLogger().log(Level.WARNING, sw.toString());
  }

  private static void sendMsg(CommandSender sender, String msg){
    sender.sendMessage("[Firewall] " + ChatColor.GRAY + msg + ChatColor.RESET);
  }
}

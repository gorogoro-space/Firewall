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
import java.util.HashMap;
import java.util.List;
import java.util.logging.Level;

import org.bukkit.Bukkit;
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
  private List<String> unblockUuidList = new ArrayList<String>();

  @Override
  public boolean onCommand( CommandSender sender, Command commandInfo, String label, String[] args) {
    // Return true:Success false:Show the usage set in plugin.yml
    try{
      if(!commandInfo.getName().equals("firewall")) {
        return true;
      }

      if(!sender.isOp()) {
        return true;
      }

      if(args.length != 1) {
        return false;
      }

      if(args[0] == "reload") {
        onDisable();
        onEnable();
        sender.sendMessage("Reload complete.");
      }

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
      unblockUuidList = config.getStringList("list-unblock-uuid");

    } catch (Exception e) {
      logStackTrace(e);
    }
  }

  @EventHandler
  public void onAsyncPlayerPreLoginEvent(AsyncPlayerPreLoginEvent event){
    try {
      String addr = event.getAddress().getHostAddress().toString();

      if(unblockUuidList.contains(event.getUniqueId().toString()) == false) {
        for(ArrayList<Long> range:blockNetsetIpv4List) {
          if(range.get(0) <= ipv4ToLong(addr) && ipv4ToLong(addr) <= range.get(1)) {
            event.disallow(Result.KICK_OTHER, config.getString("message-kick"));
          }
        }
      }
    } catch (Exception e) {
      logStackTrace(e);
    }
  }

  private void storeBlockNetsetList(Connection con) throws SQLException {
    try {
      File dest = new File(getDataFolder() + File.separator + "stored" + File.separator);
      if(!dest.exists()) {
        dest.mkdir();
      }
      for(String fileName : config.getStringList("list-block-netset-file")){
        File f = new File(getDataFolder() + File.separator + fileName);
        if(!f.exists()) {
          continue;
        }
        getLogger().info("Found. path=" + f.getPath());

        List<String> lines = Files.readAllLines(f.toPath());
        HashMap<String,PreparedStatement> prepStmt = new HashMap<>();
        prepStmt.put("select",con.prepareStatement("SELECT 1 FROM block_list WHERE cidr = ?;"));
        prepStmt.put("insert",con.prepareStatement("INSERT INTO block_list(cidr, start, end) VALUES (?, ?, ?);"));
        ResultSet rs;
        String[] range;
        int rows = 0;
        for(String line: lines) {
          if(!isIpv4(line)) {
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
      if(str.length() < 7 || str.length() > 18) {
        return false;
      }
      String[] arrIp = str.split("/");
      if (InetAddress.getByName(arrIp[0]) instanceof Inet4Address) {
        return true;
      }
    } catch (UnknownHostException e) {
      return false;
    }
    return false;
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
}

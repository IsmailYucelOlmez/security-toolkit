using System.Data.SqlClient;

class Db {
    // ruleid: csharp-hardcoded-connection-string-password
    const string A = "Server=db;User Id=sa;Password=abcd1234;";
    // ruleid: csharp-hardcoded-connection-string-password
    const string B = "Server=db;Pwd=abcd1234";
    // ok: csharp-hardcoded-connection-string-password
    const string C = "Server=db;Integrated Security=true;";
    // ok: csharp-hardcoded-connection-string-password
    const string D = "Server=db;Password={0};";

    string Code() {
        // ok: csharp-hardcoded-connection-string-password
        string password = GetPassword();
        return password;
    }

    SqlCommand Find(SqlConnection c, string n) {
        // ruleid: csharp-sql-string-concat
        var a = new SqlCommand("SELECT * FROM u WHERE n='" + n + "'", c);
        // ok: csharp-sql-string-concat
        return new SqlCommand("SELECT * FROM u WHERE n=@n", c);
    }

    string GetPassword() { return ""; }
}

using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace FDS.Migrations
{
    public partial class SeedRole : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[] { "727017c5-c40a-42d2-9b9c-281a3afca043", "1", "Admin", "Admin" });

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[] { "f58dc6b3-4b89-48da-9a9e-4979783f6d78", "2", "Pilot", "Pilot" });
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "727017c5-c40a-42d2-9b9c-281a3afca043");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "f58dc6b3-4b89-48da-9a9e-4979783f6d78");
        }
    }
}

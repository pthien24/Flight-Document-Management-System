using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace FDS.Data.Migrations
{
    public partial class AddRoles : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "a6d03253-ccd5-4bd7-b9ce-ee6b2009819f");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "c227d90d-5ada-468a-93fa-640d67f6bc4c");

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "1483f620-9aa2-4dec-abb6-5464d06698b5", "4", "Attendant", "Attendant" },
                    { "1d0be4df-f812-4172-8ad9-724bfca68913", "1", "Admin", "Admin" },
                    { "394975b6-b989-4b7c-b4a0-6460f25c497c", "2", "Pilot", "Pilot" },
                    { "44bf758e-b939-4b9b-87e0-bd804b1e9ab7", "3", "Emloyee", "Emloyee" }
                });
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "1483f620-9aa2-4dec-abb6-5464d06698b5");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "1d0be4df-f812-4172-8ad9-724bfca68913");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "394975b6-b989-4b7c-b4a0-6460f25c497c");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "44bf758e-b939-4b9b-87e0-bd804b1e9ab7");

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[] { "a6d03253-ccd5-4bd7-b9ce-ee6b2009819f", "1", "Admin", "Admin" });

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[] { "c227d90d-5ada-468a-93fa-640d67f6bc4c", "2", "Pilot", "Pilot" });
        }
    }
}

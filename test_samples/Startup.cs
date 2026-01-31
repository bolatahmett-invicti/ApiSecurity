// Sample ASP.NET Core Startup/Program Configuration
// Demonstrates startup configuration patterns the scanner should detect

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace SampleApi
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // Add controllers
            services.AddControllers();
            
            // Add authentication
            services.AddAuthentication("Bearer")
                .AddJwtBearer(options =>
                {
                    options.Authority = "https://auth.example.com";
                    options.Audience = "api";
                });
            
            // Add authorization
            services.AddAuthorization(options =>
            {
                options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
            });
            
            // Add Swagger/OpenAPI
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new() { Title = "Sample API", Version = "v1" });
            });
            
            // Add CORS
            services.AddCors(options =>
            {
                options.AddPolicy("AllowAll", builder =>
                    builder.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader());
            });
            
            // Add health checks
            services.AddHealthChecks()
                .AddCheck("database", () => HealthCheckResult.Healthy())
                .AddCheck("redis", () => HealthCheckResult.Healthy());
            
            // Add SignalR
            services.AddSignalR();
            
            // Add gRPC
            services.AddGrpc();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            // Use HTTPS redirection
            app.UseHttpsRedirection();

            // Enable Swagger
            app.UseSwagger();
            app.UseSwaggerUI(c =>
            {
                c.SwaggerEndpoint("/swagger/v1/swagger.json", "Sample API V1");
            });

            // Use routing
            app.UseRouting();

            // Use CORS
            app.UseCors("AllowAll");

            // Use authentication & authorization
            app.UseAuthentication();
            app.UseAuthorization();

            // Map endpoints
            app.UseEndpoints(endpoints =>
            {
                // Map controllers
                endpoints.MapControllers();
                
                // Map health checks
                endpoints.MapHealthChecks("/health");
                endpoints.MapHealthChecks("/health/ready");
                endpoints.MapHealthChecks("/health/live");
                
                // Map SignalR hubs
                endpoints.MapHub<ChatHub>("/hubs/chat");
                endpoints.MapHub<NotificationHub>("/hubs/notifications");
                
                // Map gRPC services
                endpoints.MapGrpcService<GreeterService>();
                endpoints.MapGrpcService<OrderService>();
            });
        }
    }

    // ==========================================================================
    // Program.cs - .NET 6+ Minimal API Pattern
    // ==========================================================================
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            builder.Services.AddControllers();
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();

            var app = builder.Build();

            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();
            app.UseAuthorization();

            // Minimal API endpoints
            app.MapGet("/api/v2/health", () => new { status = "healthy" });
            app.MapGet("/api/v2/version", () => new { version = "2.0.0" });
            
            // User endpoints
            app.MapGet("/api/v2/users", () => new { users = new string[] { } });
            app.MapGet("/api/v2/users/{id}", (int id) => new { id = id });
            app.MapPost("/api/v2/users", (UserDto user) => new { id = 1 });
            app.MapPut("/api/v2/users/{id}", (int id, UserDto user) => new { updated = true });
            app.MapDelete("/api/v2/users/{id}", (int id) => new { deleted = true });
            
            // Payment endpoints - HIGH RISK
            app.MapPost("/api/v2/payments/charge", (PaymentDto payment) => 
                new { transactionId = "txn_123" });
            
            // Admin endpoints - CRITICAL
            app.MapDelete("/admin/v2/users/{id}", (int id) => new { deleted = true });
            app.MapPost("/admin/v2/reset", () => new { reset = true });

            app.MapControllers();

            app.Run();
        }
    }
}

FROM mcr.microsoft.com/dotnet/core/aspnet:3.1-buster-slim AS base
WORKDIR /app
EXPOSE 80

FROM mcr.microsoft.com/dotnet/core/sdk:3.1-buster AS build
WORKDIR /src
COPY ["src/bluenumberis.STS.Identity/bluenumberis.STS.Identity.csproj", "src/bluenumberis.STS.Identity/"]
COPY ["src/bluenumberis.Admin.EntityFramework.Shared/bluenumberis.Admin.EntityFramework.Shared.csproj", "src/bluenumberis.Admin.EntityFramework.Shared/"]
COPY ["src/bluenumberis.Admin.EntityFramework.SqlServer/bluenumberis.Admin.EntityFramework.SqlServer.csproj", "src/bluenumberis.Admin.EntityFramework.SqlServer/"]
COPY ["src/bluenumberis.Admin.EntityFramework.PostgreSQL/bluenumberis.Admin.EntityFramework.PostgreSQL.csproj", "src/bluenumberis.Admin.EntityFramework.PostgreSQL/"]
COPY ["src/bluenumberis.Admin.EntityFramework.MySql/bluenumberis.Admin.EntityFramework.MySql.csproj", "src/bluenumberis.Admin.EntityFramework.MySql/"]
RUN dotnet restore "src/bluenumberis.STS.Identity/bluenumberis.STS.Identity.csproj"
COPY . .
WORKDIR "/src/src/bluenumberis.STS.Identity"
RUN dotnet build "bluenumberis.STS.Identity.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "bluenumberis.STS.Identity.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENV ASPNETCORE_FORWARDEDHEADERS_ENABLED=true
ENTRYPOINT ["dotnet", "bluenumberis.STS.Identity.dll"]
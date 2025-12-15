using CloudinaryDotNet;
using CloudinaryDotNet.Actions;

namespace Gallery.Services
{
    public class CloudinaryService
    {
        private readonly Cloudinary _cloudinary;
        private readonly IConfiguration _config;

        public CloudinaryService(IConfiguration config)
        {
            _config = config;
            
            var cloudName = Environment.GetEnvironmentVariable("CLOUDINARY_CLOUD_NAME") 
                ?? _config["Cloudinary:CloudName"];
            var apiKey = Environment.GetEnvironmentVariable("CLOUDINARY_API_KEY") 
                ?? _config["Cloudinary:ApiKey"];
            var apiSecret = Environment.GetEnvironmentVariable("CLOUDINARY_API_SECRET") 
                ?? _config["Cloudinary:ApiSecret"];

            if (string.IsNullOrEmpty(cloudName) || string.IsNullOrEmpty(apiKey))
            {
                throw new InvalidOperationException(
                    "Cloudinary configuration is missing! Check your .env file."
                );
            }

            var account = new Account(cloudName, apiKey, apiSecret);
            _cloudinary = new Cloudinary(account);
        }

        public async Task<CloudinaryUploadResult> UploadProfilePictureAsync(
            IFormFile file, 
            string userId)
        {
            if (!IsValidImageFile(file))
            {
                throw new ArgumentException("Invalid file type. Only images are allowed.");
            }

            if (file.Length > 5 * 1024 * 1024)
            {
                throw new ArgumentException("File size exceeds 5MB limit.");
            }

            using var stream = file.OpenReadStream();

            var uploadParams = new ImageUploadParams
            {
                File = new FileDescription(file.FileName, stream),
                Folder = "gallery/profile-pictures",
                PublicId = $"user_{userId}_{Guid.NewGuid()}",
                Transformation = new Transformation()
                    .Width(500)
                    .Height(500)
                    .Crop("fill")
                    .Gravity("face")
                    .Quality("auto:good"),
                Overwrite = true
            };

            var uploadResult = await _cloudinary.UploadAsync(uploadParams);

            if (uploadResult.Error != null)
            {
                throw new Exception($"Cloudinary upload error: {uploadResult.Error.Message}");
            }

            return new CloudinaryUploadResult
            {
                Url = uploadResult.SecureUrl.ToString(),
                PublicId = uploadResult.PublicId,
                Width = uploadResult.Width,
                Height = uploadResult.Height,
                Format = uploadResult.Format
            };
        }

        public async Task<CloudinaryPostUploadResult> UploadPostMediaAsync(
            IFormFile file,
            string userId,
            string artistName)
        {
            var isVideo = IsVideoFile(file);
            var isImage = IsValidImageFile(file);

            if (!isVideo && !isImage)
            {
                throw new ArgumentException("Invalid file type. Only images and videos are allowed.");
            }

            var maxSize = isVideo ? 50 * 1024 * 1024 : 10 * 1024 * 1024; 
            if (file.Length > maxSize)
            {
                throw new ArgumentException($"File size exceeds {maxSize / (1024 * 1024)}MB limit.");
            }

            using var stream = file.OpenReadStream();

            var publicId = $"user_{userId}_post_{Guid.NewGuid()}";
            var folder = isVideo ? "art-gallery/posts/videos" : "art-gallery/posts/images";

            if (isImage)
            {
                var imageParams = new ImageUploadParams
                {
                    File = new FileDescription(file.FileName, stream),
                    Folder = folder,
                    PublicId = publicId,
                    Transformation = new Transformation()
                        .Quality("auto:good")
                        .FetchFormat("auto"),
                    Context = new StringDictionary { { "artist", artistName } }
                };
                var imageResult = await _cloudinary.UploadAsync(imageParams);

                if (imageResult.Error != null)
                throw new Exception($"Upload error: {imageResult.Error.Message}");

                var normalUrl = imageResult.SecureUrl.ToString();
                var watermarkedUrl = GenerateWatermarkedUrl(imageResult.PublicId, artistName, false);
                var downloadUrl = GenerateDownloadUrl(imageResult.PublicId, artistName, false);

                return new CloudinaryPostUploadResult
                {
                    Url = normalUrl,
                    WatermarkedUrl = watermarkedUrl,
                    DownloadUrl = downloadUrl,
                    PublicId = imageResult.PublicId,
                    Width = imageResult.Width,
                    Height = imageResult.Height,
                    Format = imageResult.Format,
                    MediaType = "image",
                    FileSizeBytes = imageResult.Bytes,
                    DurationSeconds = null
                };
            }
            else
            {
                var videoParams = new VideoUploadParams
                {
                    File = new FileDescription(file.FileName, stream),
                    Folder = folder,
                    PublicId = publicId,
                    Transformation = new Transformation()
                        .Quality("auto:good"),
                    Context = new StringDictionary { { "artist", artistName } }
                };

                var videoResult = await _cloudinary.UploadAsync(videoParams);

                if (videoResult.Error != null)
                throw new Exception($"Upload error: {videoResult.Error.Message}");

                var normalUrl = videoResult.SecureUrl.ToString();
                var watermarkedUrl = GenerateWatermarkedUrl(videoResult.PublicId, artistName, true);
                var downloadUrl = GenerateDownloadUrl(videoResult.PublicId, artistName, true);

                return new CloudinaryPostUploadResult
                {
                    Url = normalUrl,
                    WatermarkedUrl = watermarkedUrl,
                    DownloadUrl = downloadUrl,
                    PublicId = videoResult.PublicId,
                    Width = videoResult.Width,
                    Height = videoResult.Height,
                    Format = videoResult.Format,
                    MediaType = "video",
                    FileSizeBytes = videoResult.Bytes,
                    DurationSeconds = (int?)videoResult.Duration
                };
            }

           
        }
        private string GenerateWatermarkedUrl(string publicId, string artistName, bool isVideo)
        {
            var transformation = new Transformation();

            if (isVideo)
            {
                transformation
                    .Overlay(new TextLayer()
                        .Text($"© {artistName}")
                        .FontFamily("Arial")
                        .FontSize(30)
                        .FontWeight("bold"))
                    .Gravity("south_east")
                    .X(20)
                    .Y(20)
                    .Opacity(70);
            }
            else
            {
                transformation
                    .Overlay(new TextLayer()
                        .Text($"© {artistName}")
                        .FontFamily("Arial")
                        .FontSize(40)
                        .FontWeight("bold"))
                    .Gravity("center")
                    .Opacity(50);
            }

            return _cloudinary.Api.UrlImgUp
                .Transform(transformation)
                .BuildUrl(publicId);
        }
        private string GenerateDownloadUrl(string publicId, string artistName, bool isVideo)
        {
            var transformation = new Transformation();

            if (isVideo)
            {
                transformation
                    .Quality("auto:low")
                    .VideoCodec("auto")
                    .Overlay(new TextLayer()
                        .Text($"© {artistName} - Visit Gallery.2ao1.space")
                        .FontFamily("Arial")
                        .FontSize(35)
                        .FontWeight("bold"))
                    .Gravity("center")
                    .Opacity(80);
            }
            else
            {
                transformation
                    .Effect("pixelate:10") 
                    .Quality("auto:low")
                    .Overlay(new TextLayer()
                        .Text($"© {artistName}\nDownload blocked\nVisit Gallery.2ao1.space")
                        .FontFamily("Arial")
                        .FontSize(50)
                        .FontWeight("bold"))
                    .Gravity("center")
                    .Opacity(90);
            }

            return _cloudinary.Api.UrlImgUp
                .Transform(transformation)
                .BuildUrl(publicId);
        }

        public async Task<bool> DeleteFileAsync(string publicId)
        {
            var deleteParams = new DeletionParams(publicId)
            {
                ResourceType = ResourceType.Image
            };

            var result = await _cloudinary.DestroyAsync(deleteParams);
            return result.Result == "ok";
        }

        private bool IsValidImageFile(IFormFile file)
        {
            var allowedExtensions = new[] { ".jpg", ".jpeg", ".png", ".gif", ".webp" };
            var extension = Path.GetExtension(file.FileName).ToLowerInvariant();
            return allowedExtensions.Contains(extension);
        }

        private bool IsVideoFile(IFormFile file)
        {
            var allowedExtensions = new[] { ".mp4", ".mov", ".avi", ".webm" };
            var extension = Path.GetExtension(file.FileName).ToLowerInvariant();
            return allowedExtensions.Contains(extension);
        }
    }

    public class CloudinaryUploadResult
    {
        public string Url { get; set; } = string.Empty;
        public string PublicId { get; set; } = string.Empty;
        public int Width { get; set; }
        public int Height { get; set; }
        public string Format { get; set; } = string.Empty;
    }

    public class CloudinaryPostUploadResult : CloudinaryUploadResult
    {
        public string WatermarkedUrl { get; set; } = string.Empty;
        public string DownloadUrl { get; set; } = string.Empty;
        public string MediaType { get; set; } = string.Empty;
        public long FileSizeBytes { get; set; }
        public int? DurationSeconds { get; set; }
    }
}
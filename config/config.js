const msBuildVersion = "5.13.0.66756";
const cliVersion = "4.8.0.2856"; // Has to be the same version as the one embedded in the Scanner for MSBuild

const scannerUrlCommon =
  `https://github.com/SonarSource/sonar-scanner-msbuild/releases/download/${msBuildVersion}/` +
  `sonar-scanner-msbuild-${msBuildVersion}`;

exports.scanner = {
  msBuildVersion,
  cliVersion,
  classicUrl: `${scannerUrlCommon}-net46.zip`,
  dotnetUrl: `${scannerUrlCommon}-netcoreapp3.0.zip`,
};

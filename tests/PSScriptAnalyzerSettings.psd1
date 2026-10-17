@{
    Severity     = @('Error', 'Warning')
    IncludeRules = @('*')
    # Test helpers are throwaway builders and Pester scriptblocks, so these style rules add noise only.
    ExcludeRules = @('PSUseShouldProcessForStateChangingFunctions', 'PSUseSingularNouns', 'PSReviewUnusedParameter')
}

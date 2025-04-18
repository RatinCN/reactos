/*
 *  FreeLoader
 *  Copyright (C) 1998-2003  Brian Palmer  <brianp@sginet.com>
 *  Copyright (C) 2009       Hervé Poussineau  <hpoussin@reactos.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _M_ARM
#include <freeldr.h>

#include <debug.h>
DBG_DEFAULT_CHANNEL(FILESYSTEM);

#define SECTORSIZE 2048
#define TAG_ISO_VOLUME 'VosI'
#define TAG_ISO_BUFFER 'BosI'
#define TAG_ISO_FILE 'FosI'

typedef struct _ISO_VOLUME_INFO
{
    ULONG PvdDirectorySector;
    ULONG PvdDirectoryLength;
    ULONG DirectoryPathLength;
    ULONG DirectoryLength;
    PVOID DirectoryBuffer;
    UCHAR DirectoryPath[261];
} ISO_VOLUME_INFO, *PISO_VOLUME_INFO;

static PISO_VOLUME_INFO IsoVolumes[MAX_FDS];

static
PCSTR
IsoLastPathSeparator(
    _In_ PCSTR Path)
{
    PCSTR Last = NULL;

    ASSERT(Path != NULL);

    while (*Path != ANSI_NULL)
    {
        if (*Path == '\\' || *Path == '/')
            Last = Path;

        ++Path;
    }

    return Last;
}

static BOOLEAN IsoSearchDirectoryBufferForFile(PVOID DirectoryBuffer, ULONG DirectoryLength, PCHAR FileName, PISO_FILE_INFO IsoFileInfoPointer)
{
    PDIR_RECORD    Record;
    ULONG        Offset;
    ULONG i;
    CHAR Name[32];

    TRACE("IsoSearchDirectoryBufferForFile() DirectoryBuffer = 0x%x DirectoryLength = %d FileName = %s\n", DirectoryBuffer, DirectoryLength, FileName);

    Offset = 0;
    Record = (PDIR_RECORD)DirectoryBuffer;
    while (TRUE)
    {
        Offset = Offset + Record->RecordLength;
        Record = (PDIR_RECORD)((ULONG_PTR)DirectoryBuffer + Offset);

        if (Record->RecordLength == 0)
        {
            Offset = ROUND_UP(Offset, SECTORSIZE);
            Record = (PDIR_RECORD)((ULONG_PTR)DirectoryBuffer + Offset);
        }

        if (Offset >= DirectoryLength)
            return FALSE;

        if (Record->FileIdLength == 1 && Record->FileId[0] == 0)
        {
            TRACE("Name '.'\n");
        }
        else if (Record->FileIdLength == 1 && Record->FileId[0] == 1)
        {
            TRACE("Name '..'\n");
        }
        else
        {
            for (i = 0; i < Record->FileIdLength && Record->FileId[i] != ';'; i++)
                Name[i] = Record->FileId[i];
            Name[i] = ANSI_NULL;
            TRACE("Name '%s'\n", Name);

            if (strlen(FileName) == strlen(Name) && _stricmp(FileName, Name) == 0)
            {
                IsoFileInfoPointer->FileStart = Record->ExtentLocationL;
                IsoFileInfoPointer->FileSize = Record->DataLengthL;
                IsoFileInfoPointer->FilePointer = 0;
                IsoFileInfoPointer->Directory = !!(Record->FileFlags & 0x02);

                return TRUE;
            }

        }
    }

    return FALSE;
}


/*
 * IsoBufferDirectory()
 * This function allocates a buffer, reads the specified directory
 * and returns a pointer to that buffer into pDirectoryBuffer. The
 * function returns an ARC error code. The directory is specified
 * by its starting sector and length.
 */
static ARC_STATUS IsoBufferDirectory(ULONG DeviceId, ULONG DirectoryStartSector, ULONG DirectoryLength,
    PVOID* pDirectoryBuffer)
{
    PVOID DirectoryBuffer;
    ULONG SectorCount;
    LARGE_INTEGER Position;
    ULONG Count;
    ARC_STATUS Status;

    TRACE("IsoBufferDirectory() DirectoryStartSector = %d DirectoryLength = %d\n", DirectoryStartSector, DirectoryLength);

    SectorCount = ROUND_UP(DirectoryLength, SECTORSIZE) / SECTORSIZE;
    TRACE("Trying to read (DirectoryCount) %d sectors.\n", SectorCount);

    //
    // Attempt to allocate memory for directory buffer
    //
    TRACE("Trying to allocate (DirectoryLength) %d bytes.\n", DirectoryLength);
    DirectoryBuffer = FrLdrTempAlloc(DirectoryLength, TAG_ISO_BUFFER);
    if (!DirectoryBuffer)
        return ENOMEM;

    //
    // Now read directory contents into DirectoryBuffer
    //
    Position.HighPart = 0;
    Position.LowPart = DirectoryStartSector * SECTORSIZE;
    Status = ArcSeek(DeviceId, &Position, SeekAbsolute);
    if (Status != ESUCCESS)
    {
        FrLdrTempFree(DirectoryBuffer, TAG_ISO_BUFFER);
        return Status;
    }
    Status = ArcRead(DeviceId, DirectoryBuffer, SectorCount * SECTORSIZE, &Count);
    if (Status != ESUCCESS || Count != SectorCount * SECTORSIZE)
    {
        FrLdrTempFree(DirectoryBuffer, TAG_ISO_BUFFER);
        return EIO;
    }

    *pDirectoryBuffer = DirectoryBuffer;
    return ESUCCESS;
}

/*
 * IsoLookupFile()
 * This function searches the file system for the
 * specified filename and fills in an ISO_FILE_INFO structure
 * with info describing the file, etc. returns ARC error code
 */
static ARC_STATUS IsoLookupFile(PCSTR FileName, ULONG DeviceId, PISO_FILE_INFO IsoFileInfo)
{
    PCSTR FullPath = FileName;
    PISO_VOLUME_INFO Volume;
    PCSTR FileNameStr;
    ULONG i, DirectoryPathLength, DirectorySector, DirectoryLength;
    PVOID DirectoryBuffer;
    ULONG NumberOfPathParts;
    CHAR PathBuffer[261];
    CHAR* PathPart;
    ARC_STATUS Status;
    BOOLEAN DoFullLookup;

    TRACE("IsoLookupFile() FileName = %s\n", FileName);

    Volume = IsoVolumes[DeviceId];

    /*
     * Extract the file name
     * '\test.ini' --> 'test.ini'
     * '\folder\app.exe' --> 'app.exe'
     */
    FileNameStr = IsoLastPathSeparator(FileName) + 1;

    /*
     * Extract the directory path, including trailing slash
     * '\test.ini' --> '\'
     * '\folder\app.exe' --> '\folder\'
     */
    DirectoryPathLength = FileNameStr - FileName;

    /* See if this directory has been buffered before */
    DoFullLookup = (DirectoryPathLength != Volume->DirectoryPathLength) ||
                   !RtlEqualMemory(FileName, Volume->DirectoryPath, DirectoryPathLength);
    if (!DoFullLookup)
    {
        PathPart = (CHAR*)FileNameStr;
        DirectoryBuffer = Volume->DirectoryBuffer;
        DirectoryLength = Volume->DirectoryLength;

        NumberOfPathParts = 1;
    }
    else
    {
        PathPart = PathBuffer;
        DirectorySector = Volume->PvdDirectorySector;
        DirectoryLength = Volume->PvdDirectoryLength;

        /* Skip leading path separator, if any */
        if (*FileName == '\\' || *FileName == '/')
            ++FileName;

        /* Figure out how many sub-directories we are nested in */
        NumberOfPathParts = FsGetNumPathParts(FileName);
    }

    //
    // Loop once for each part
    //
    for (i=0; i<NumberOfPathParts; i++)
    {
        if (DoFullLookup)
        {
            /* Get first path part */
            FsGetFirstNameFromPath(PathPart, FileName);

            /* Advance to the next part of the path */
            while ((*FileName != ANSI_NULL) && (*FileName != '\\') && (*FileName != '/'))
            {
                FileName++;
            }
            FileName++;

            /* Buffer the directory contents */
            Status = IsoBufferDirectory(DeviceId,
                                        DirectorySector,
                                        DirectoryLength,
                                        &DirectoryBuffer);
            if (Status != ESUCCESS)
                return Status;

            /* Save the directory buffer */
            if ((i + 1) >= NumberOfPathParts)
            {
                if (Volume->DirectoryBuffer)
                    FrLdrTempFree(Volume->DirectoryBuffer, TAG_ISO_BUFFER);

                Volume->DirectoryPathLength = DirectoryPathLength;
                Volume->DirectoryBuffer = DirectoryBuffer;
                Volume->DirectoryLength = DirectoryLength;

                RtlCopyMemory(Volume->DirectoryPath, FullPath, DirectoryPathLength);
            }
        }

        /* Search for file name in directory */
        if (!IsoSearchDirectoryBufferForFile(DirectoryBuffer,
                                             DirectoryLength,
                                             PathPart,
                                             IsoFileInfo))
        {
            /* Free the directory buffer that wasn't cached */
            if ((i + 1) < NumberOfPathParts)
            {
                ASSERT(DirectoryBuffer != Volume->DirectoryBuffer);
                FrLdrTempFree(DirectoryBuffer, TAG_ISO_BUFFER);
            }
            return ENOENT;
        }

        //
        // If we have another sub-directory to go then
        // grab the start sector and file size
        //
        if ((i+1) < NumberOfPathParts)
        {
            FrLdrTempFree(DirectoryBuffer, TAG_ISO_BUFFER);

            DirectorySector = IsoFileInfo->FileStart;
            DirectoryLength = IsoFileInfo->FileSize;
        }
    }

    return ESUCCESS;
}

static
ARC_STATUS IsoClose(ULONG FileId)
{
    PISO_FILE_INFO FileHandle = FsGetDeviceSpecific(FileId);
    FrLdrTempFree(FileHandle, TAG_ISO_FILE);
    return ESUCCESS;
}

static
ARC_STATUS IsoGetFileInformation(ULONG FileId, FILEINFORMATION* Information)
{
    PISO_FILE_INFO FileHandle = FsGetDeviceSpecific(FileId);

    RtlZeroMemory(Information, sizeof(*Information));
    Information->EndingAddress.LowPart = FileHandle->FileSize;
    Information->CurrentAddress.LowPart = FileHandle->FilePointer;

    TRACE("IsoGetFileInformation(%lu) -> FileSize = %lu, FilePointer = 0x%lx\n",
          FileId, Information->EndingAddress.LowPart, Information->CurrentAddress.LowPart);

    return ESUCCESS;
}

static
ARC_STATUS IsoOpen(CHAR* Path, OPENMODE OpenMode, ULONG* FileId)
{
    PISO_FILE_INFO FileHandle;
    ULONG DeviceId;
    ARC_STATUS Status;

    if (OpenMode != OpenReadOnly)
        return EACCES;

    DeviceId = FsGetDeviceId(*FileId);

    TRACE("IsoOpen() FileName = %s\n", Path);

    FileHandle = FrLdrTempAlloc(sizeof(*FileHandle), TAG_ISO_FILE);
    if (!FileHandle)
        return ENOMEM;

    Status = IsoLookupFile(Path, DeviceId, FileHandle);
    if (Status != ESUCCESS)
    {
        FrLdrTempFree(FileHandle, TAG_ISO_FILE);
        return ENOENT;
    }

    FsSetDeviceSpecific(*FileId, FileHandle);
    return ESUCCESS;
}

static
ARC_STATUS IsoRead(ULONG FileId, VOID* Buffer, ULONG N, ULONG* Count)
{
    ARC_STATUS Status;
    PISO_FILE_INFO FileHandle = FsGetDeviceSpecific(FileId);
    UCHAR SectorBuffer[SECTORSIZE];
    LARGE_INTEGER Position;
    ULONG DeviceId;
    ULONG SectorNumber;
    ULONG OffsetInSector;
    ULONG LengthInSector;
    ULONG NumberOfSectors;
    ULONG BytesRead;

    TRACE("IsoRead() Buffer = %p, N = %lu\n", Buffer, N);

    DeviceId = FsGetDeviceId(FileId);
    *Count = 0;

    //
    // If the user is trying to read past the end of
    // the file then return success with Count == 0.
    //
    if (FileHandle->FilePointer >= FileHandle->FileSize)
    {
        return ESUCCESS;
    }

    //
    // If the user is trying to read more than there is to read
    // then adjust the amount to read.
    //
    if (FileHandle->FilePointer + N > FileHandle->FileSize)
    {
        N = FileHandle->FileSize - FileHandle->FilePointer;
    }

    //
    // Ok, now we have to perform at most 3 calculations
    // I'll draw you a picture (using nifty ASCII art):
    //
    // CurrentFilePointer -+
    //                     |
    //    +----------------+
    //    |
    // +-----------+-----------+-----------+-----------+
    // | Sector  1 | Sector  2 | Sector  3 | Sector  4 |
    // +-----------+-----------+-----------+-----------+
    //    |                                    |
    //    +---------------+--------------------+
    //                    |
    // N -----------------+
    //
    // 1 - The first calculation (and read) will align
    //     the file pointer with the next sector
    //     boundary (if we are supposed to read that much)
    // 2 - The next calculation (and read) will read
    //     in all the full sectors that the requested
    //     amount of data would cover (in this case
    //     sectors 2 & 3).
    // 3 - The last calculation (and read) would read
    //     in the remainder of the data requested out of
    //     the last sector.
    //


    //
    // Only do the first read if we
    // aren't aligned on a cluster boundary
    //
    if (FileHandle->FilePointer % SECTORSIZE)
    {
        //
        // Do the math for our first read
        //
        SectorNumber = FileHandle->FileStart + (FileHandle->FilePointer / SECTORSIZE);
        OffsetInSector = FileHandle->FilePointer % SECTORSIZE;
        LengthInSector = min(N, SECTORSIZE - OffsetInSector);

        //
        // Now do the read and update Count, N, FilePointer, & Buffer
        //
        Position.HighPart = 0;
        Position.LowPart = SectorNumber * SECTORSIZE;
        Status = ArcSeek(DeviceId, &Position, SeekAbsolute);
        if (Status != ESUCCESS)
        {
            return Status;
        }
        Status = ArcRead(DeviceId, SectorBuffer, SECTORSIZE, &BytesRead);
        if (Status != ESUCCESS || BytesRead != SECTORSIZE)
        {
            return EIO;
        }
        RtlCopyMemory(Buffer, SectorBuffer + OffsetInSector, LengthInSector);
        *Count += LengthInSector;
        N -= LengthInSector;
        FileHandle->FilePointer += LengthInSector;
        Buffer = (PVOID)((ULONG_PTR)Buffer + LengthInSector);
    }

    //
    // Do the math for our second read (if any data left)
    //
    if (N > 0)
    {
        //
        // Determine how many full clusters we need to read
        //
        NumberOfSectors = (N / SECTORSIZE);

        SectorNumber = FileHandle->FileStart + (FileHandle->FilePointer / SECTORSIZE);

        //
        // Now do the read and update Count, N, FilePointer, & Buffer
        //
        Position.HighPart = 0;
        Position.LowPart = SectorNumber * SECTORSIZE;
        Status = ArcSeek(DeviceId, &Position, SeekAbsolute);
        if (Status != ESUCCESS)
        {
            return Status;
        }
        Status = ArcRead(DeviceId, Buffer, NumberOfSectors * SECTORSIZE, &BytesRead);
        if (Status != ESUCCESS || BytesRead != NumberOfSectors * SECTORSIZE)
        {
            return EIO;
        }

        *Count += NumberOfSectors * SECTORSIZE;
        N -= NumberOfSectors * SECTORSIZE;
        FileHandle->FilePointer += NumberOfSectors * SECTORSIZE;
        Buffer = (PVOID)((ULONG_PTR)Buffer + NumberOfSectors * SECTORSIZE);
    }

    //
    // Do the math for our third read (if any data left)
    //
    if (N > 0)
    {
        SectorNumber = FileHandle->FileStart + (FileHandle->FilePointer / SECTORSIZE);

        //
        // Now do the read and update Count, N, FilePointer, & Buffer
        //
        Position.HighPart = 0;
        Position.LowPart = SectorNumber * SECTORSIZE;
        Status = ArcSeek(DeviceId, &Position, SeekAbsolute);
        if (Status != ESUCCESS)
        {
            return Status;
        }
        Status = ArcRead(DeviceId, SectorBuffer, SECTORSIZE, &BytesRead);
        if (Status != ESUCCESS || BytesRead != SECTORSIZE)
        {
            return EIO;
        }
        RtlCopyMemory(Buffer, SectorBuffer, N);
        *Count += N;
        FileHandle->FilePointer += N;
    }

    TRACE("IsoRead() done\n");

    return ESUCCESS;
}

static
ARC_STATUS IsoSeek(ULONG FileId, LARGE_INTEGER* Position, SEEKMODE SeekMode)
{
    PISO_FILE_INFO FileHandle = FsGetDeviceSpecific(FileId);
    LARGE_INTEGER NewPosition = *Position;

    switch (SeekMode)
    {
        case SeekAbsolute:
            break;
        case SeekRelative:
            NewPosition.QuadPart += (ULONGLONG)FileHandle->FilePointer;
            break;
        default:
            ASSERT(FALSE);
            return EINVAL;
    }

    if (NewPosition.HighPart != 0)
        return EINVAL;
    if (NewPosition.LowPart >= FileHandle->FileSize)
        return EINVAL;

    FileHandle->FilePointer = NewPosition.LowPart;
    return ESUCCESS;
}

static const DEVVTBL Iso9660FuncTable =
{
    IsoClose,
    IsoGetFileInformation,
    IsoOpen,
    IsoRead,
    IsoSeek,
    L"cdfs",
};

const DEVVTBL* IsoMount(ULONG DeviceId)
{
    UCHAR Buffer[SECTORSIZE];
    PPVD Pvd = (PPVD)Buffer;
    LARGE_INTEGER Position;
    ULONG Count;
    ARC_STATUS Status;
    PISO_VOLUME_INFO Volume;

    TRACE("Enter IsoMount(%lu)\n", DeviceId);

    /*
     * Read the Primary Volume Descriptor
     */
    Position.HighPart = 0;
    Position.LowPart = 16 * SECTORSIZE;
    Status = ArcSeek(DeviceId, &Position, SeekAbsolute);
    if (Status != ESUCCESS)
        return NULL;
    Status = ArcRead(DeviceId, Pvd, SECTORSIZE, &Count);
    if (Status != ESUCCESS || Count < sizeof(PVD))
        return NULL;

    /* Check if the PVD is valid */
    if (!(Pvd->VdType == 1 && RtlEqualMemory(Pvd->StandardId, "CD001", 5) && Pvd->VdVersion == 1))
    {
        WARN("Unrecognized CDROM format\n");
        return NULL;
    }
    if (Pvd->LogicalBlockSizeL != SECTORSIZE)
    {
        ERR("Unsupported LogicalBlockSize %u\n", Pvd->LogicalBlockSizeL);
        return NULL;
    }

    Count = (ULONG)((ULONGLONG)Pvd->VolumeSpaceSizeL * SECTORSIZE / 1024 / 1024);
    TRACE("Recognized ISO9660 drive, size %lu MB (%lu sectors)\n",
          Count, Pvd->VolumeSpaceSizeL);

    Volume = FrLdrTempAlloc(sizeof(*Volume), TAG_ISO_VOLUME);
    if (!Volume)
        return NULL;
    RtlZeroMemory(Volume, sizeof(*Volume));

    /* Cache the PVD information */
    Volume->PvdDirectorySector = Pvd->RootDirRecord.ExtentLocationL;
    Volume->PvdDirectoryLength = Pvd->RootDirRecord.DataLengthL;

    IsoVolumes[DeviceId] = Volume;

    /* Everything OK, return the ISO9660 function table */
    return &Iso9660FuncTable;
}

#endif
